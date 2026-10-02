from __future__ import annotations

import hashlib
import json
from calendar import monthrange
from collections.abc import Iterator
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, text

from verigence_security.attendance.employee.domain import payable_days
from verigence_security.attendance.employee.errors import (
    AttendanceNotFoundError,
    AttendanceRuleError,
)
from verigence_security.attendance.employee.pdf import simple_text_pdf
from verigence_security.attendance.employee.storage import (
    AttendanceStorage,
    AttendanceStorageError,
)

_MONEY = Decimal("0.01")
_DAY = Decimal("0.01")


def _money(value: Decimal) -> Decimal:
    return value.quantize(_MONEY, rounding=ROUND_HALF_UP)


def _month_start(value: date) -> date:
    return value.replace(day=1)


def _month_end(value: date) -> date:
    start = _month_start(value)
    return start.replace(day=monthrange(start.year, start.month)[1])


def _config(connection: Connection, key: str, default: Any) -> Any:
    value = connection.execute(
        text(
            """
            SELECT config_value_json
            FROM verigence_attendance.module_configuration
            WHERE config_key=:key
            """
        ),
        {"key": key},
    ).scalar_one_or_none()
    return default if value is None else value


def _weekly_offs(connection: Connection) -> set[int]:
    raw = _config(connection, "payroll.weekly_off_iso_weekdays", [7])
    if not isinstance(raw, list):
        return {7}
    values = {int(item) for item in raw if isinstance(item, (int, float, str))}
    return {item for item in values if 1 <= item <= 7} or {7}


def _holiday_dates(
    connection: Connection,
    *,
    start: date,
    end: date,
    work_location_id: UUID | None,
) -> set[date]:
    rows = connection.execute(
        text(
            """
            SELECT holiday_date
            FROM verigence_attendance.holidays
            WHERE status='ACTIVE'
              AND holiday_date BETWEEN :start AND :end
              AND (work_location_id IS NULL OR work_location_id=:location_id)
            """
        ),
        {"start": start, "end": end, "location_id": work_location_id},
    ).scalars()
    return set(rows)


def _date_range(start: date, end: date) -> Iterator[date]:
    current = start
    while current <= end:
        yield current
        current += timedelta(days=1)


def _scheduled_dates(
    connection: Connection,
    *,
    month: date,
    joining_date: date,
    work_location_id: UUID | None,
) -> list[date]:
    start = max(_month_start(month), joining_date)
    end = _month_end(month)
    if start > end:
        return []
    weekly_offs = _weekly_offs(connection)
    holidays = _holiday_dates(
        connection,
        start=start,
        end=end,
        work_location_id=work_location_id,
    )
    return [
        day
        for day in _date_range(start, end)
        if day.isoweekday() not in weekly_offs and day not in holidays
    ]


def _salary_for_month(
    connection: Connection,
    *,
    employee_id: UUID,
    month: date,
) -> dict[str, Decimal]:
    month_end = _month_end(month)
    row = connection.execute(
        text(
            """
            SELECT basic_salary,hra,allowances,other_earnings,fixed_deductions
            FROM verigence_attendance.salary_structures
            WHERE employee_id=:employee_id
              AND effective_from<=:month_end
              AND (effective_to IS NULL OR effective_to>=:month_start)
            ORDER BY effective_from DESC
            LIMIT 1
            """
        ),
        {
            "employee_id": employee_id,
            "month_start": _month_start(month),
            "month_end": month_end,
        },
    ).mappings().first()
    if row is None:
        raise AttendanceRuleError(
            "SALARY_STRUCTURE_MISSING",
            "Employee has no salary structure for this payroll month.",
            status_code=409,
        )
    return {key: Decimal(str(row[key])) for key in row}



def statutory_config_for_month(
    connection: Connection,
    *,
    month: date,
) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT *
            FROM verigence_attendance.payroll_statutory_config
            WHERE effective_from<=:month_end
              AND (effective_to IS NULL OR effective_to>=:month_start)
            ORDER BY effective_from DESC
            LIMIT 1
            """
        ),
        {
            "month_start": _month_start(month),
            "month_end": _month_end(month),
        },
    ).mappings().first()
    if row is None:
        raise AttendanceRuleError(
            "PAYROLL_STATUTORY_CONFIG_MISSING",
            "No statutory payroll configuration applies to this payroll month.",
            status_code=409,
        )
    return dict(row)


def payroll_profile_for_month(
    connection: Connection,
    *,
    employee_id: UUID,
    month: date,
) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT *
            FROM verigence_attendance.employee_payroll_profiles
            WHERE employee_id=:employee_id
              AND effective_from<=:month_end
              AND (effective_to IS NULL OR effective_to>=:month_start)
            ORDER BY effective_from DESC
            LIMIT 1
            """
        ),
        {
            "employee_id": employee_id,
            "month_start": _month_start(month),
            "month_end": _month_end(month),
        },
    ).mappings().first()
    if row is None:
        return {
            "employee_id": employee_id,
            "effective_from": _month_start(month),
            "pf_applicable": False,
            "pf_on_actual_wages": False,
            "esi_applicable": False,
            "professional_tax_state": None,
            "professional_tax_monthly": Decimal(0),
            "tds_monthly": Decimal(0),
            "tax_regime": "NEW",
            "gratuity_applicable": True,
            "uan_masked": None,
            "esic_number_masked": None,
        }
    return dict(row)


def list_payroll_profiles(connection: Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT DISTINCT ON (e.employee_id)
                       e.employee_id,e.employee_code,e.display_name,
                       p.payroll_profile_id,
                       COALESCE(p.effective_from,e.joining_date) AS effective_from,
                       p.effective_to,
                       COALESCE(p.pf_applicable,false) AS pf_applicable,
                       COALESCE(p.pf_on_actual_wages,false) AS pf_on_actual_wages,
                       COALESCE(p.esi_applicable,false) AS esi_applicable,
                       p.professional_tax_state,
                       COALESCE(p.professional_tax_monthly,0) AS professional_tax_monthly,
                       COALESCE(p.tds_monthly,0) AS tds_monthly,
                       COALESCE(p.tax_regime,'NEW') AS tax_regime,
                       COALESCE(p.gratuity_applicable,true) AS gratuity_applicable,
                       p.uan_masked,p.esic_number_masked
                FROM verigence_attendance.employees e
                LEFT JOIN verigence_attendance.employee_payroll_profiles p
                  ON p.employee_id=e.employee_id
                 AND p.effective_from<=CURRENT_DATE
                 AND (p.effective_to IS NULL OR p.effective_to>=CURRENT_DATE)
                WHERE e.employment_status='ACTIVE'
                ORDER BY e.employee_id,p.effective_from DESC NULLS LAST
                """
            )
        ).mappings()
    ]


def upsert_payroll_profile(
    connection: Connection,
    *,
    employee_id: UUID,
    effective_from: date,
    pf_applicable: bool,
    pf_on_actual_wages: bool,
    esi_applicable: bool,
    professional_tax_state: str | None,
    professional_tax_monthly: Decimal,
    tds_monthly: Decimal,
    tax_regime: str,
    gratuity_applicable: bool,
    uan_masked: str | None,
    esic_number_masked: str | None,
    actor_user_id: str,
) -> dict[str, Any]:
    exists = connection.execute(
        text(
            """
            SELECT 1 FROM verigence_attendance.employees
            WHERE employee_id=:employee_id
            """
        ),
        {"employee_id": employee_id},
    ).scalar_one_or_none()
    if exists is None:
        raise AttendanceNotFoundError("Employee not found.")
    if professional_tax_monthly < 0 or tds_monthly < 0:
        raise AttendanceRuleError(
            "PAYROLL_PROFILE_AMOUNT_INVALID",
            "Professional Tax and TDS cannot be negative.",
            status_code=400,
        )
    connection.execute(
        text(
            """
            UPDATE verigence_attendance.employee_payroll_profiles
            SET effective_to=:previous_to,updated_at_utc=now()
            WHERE employee_id=:employee_id
              AND effective_from<:effective_from
              AND (effective_to IS NULL OR effective_to>=:effective_from)
            """
        ),
        {
            "employee_id": employee_id,
            "effective_from": effective_from,
            "previous_to": effective_from - timedelta(days=1),
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.employee_payroll_profiles (
                employee_id,effective_from,pf_applicable,pf_on_actual_wages,
                esi_applicable,professional_tax_state,professional_tax_monthly,
                tds_monthly,tax_regime,gratuity_applicable,uan_masked,
                esic_number_masked,created_by_user_id
            ) VALUES (
                :employee_id,:effective_from,:pf_applicable,:pf_on_actual_wages,
                :esi_applicable,:pt_state,:pt_amount,:tds_amount,:tax_regime,
                :gratuity_applicable,:uan,:esic,CAST(:actor AS uuid)
            )
            ON CONFLICT (employee_id,effective_from) DO UPDATE SET
                pf_applicable=EXCLUDED.pf_applicable,
                pf_on_actual_wages=EXCLUDED.pf_on_actual_wages,
                esi_applicable=EXCLUDED.esi_applicable,
                professional_tax_state=EXCLUDED.professional_tax_state,
                professional_tax_monthly=EXCLUDED.professional_tax_monthly,
                tds_monthly=EXCLUDED.tds_monthly,
                tax_regime=EXCLUDED.tax_regime,
                gratuity_applicable=EXCLUDED.gratuity_applicable,
                uan_masked=EXCLUDED.uan_masked,
                esic_number_masked=EXCLUDED.esic_number_masked,
                updated_at_utc=now()
            """
        ),
        {
            "employee_id": employee_id,
            "effective_from": effective_from,
            "pf_applicable": pf_applicable,
            "pf_on_actual_wages": pf_on_actual_wages,
            "esi_applicable": esi_applicable,
            "pt_state": (professional_tax_state or "").strip().upper() or None,
            "pt_amount": professional_tax_monthly,
            "tds_amount": tds_monthly,
            "tax_regime": tax_regime,
            "gratuity_applicable": gratuity_applicable,
            "uan": (uan_masked or "").strip() or None,
            "esic": (esic_number_masked or "").strip() or None,
            "actor": actor_user_id,
        },
    )
    return payroll_profile_for_month(
        connection,
        employee_id=employee_id,
        month=effective_from,
    )


def _present_days(
    connection: Connection,
    *,
    employee_id: UUID,
    scheduled: set[date],
) -> Decimal:
    if not scheduled:
        return Decimal(0)
    rows = connection.execute(
        text(
            """
            SELECT attendance_date,present_fraction
            FROM verigence_attendance.attendance_days
            WHERE employee_id=:employee_id
              AND attendance_date BETWEEN :start AND :end
            """
        ),
        {
            "employee_id": employee_id,
            "start": min(scheduled),
            "end": max(scheduled),
        },
    ).mappings()
    return sum(
        (
            Decimal(str(row["present_fraction"]))
            for row in rows
            if row["attendance_date"] in scheduled
        ),
        Decimal(0),
    )


def _leave_days(
    connection: Connection,
    *,
    employee_id: UUID,
    scheduled: set[date],
) -> tuple[Decimal, Decimal]:
    if not scheduled:
        return Decimal(0), Decimal(0)
    rows = connection.execute(
        text(
            """
            SELECT l.start_date,l.end_date,
                   COALESCE(l.hr_approved_days,l.requested_days) AS approved_days,
                   lt.is_paid
            FROM verigence_attendance.leave_requests l
            JOIN verigence_attendance.leave_types lt ON lt.leave_type_id=l.leave_type_id
            WHERE l.employee_id=:employee_id
              AND l.status='APPROVED'
              AND l.end_date>=:start
              AND l.start_date<=:end
            """
        ),
        {
            "employee_id": employee_id,
            "start": min(scheduled),
            "end": max(scheduled),
        },
    ).mappings()
    paid = Decimal(0)
    unpaid = Decimal(0)
    for row in rows:
        full_scheduled = [
            day
            for day in _date_range(row["start_date"], row["end_date"])
            if day in scheduled
        ]
        if not full_scheduled:
            continue
        approved = Decimal(str(row["approved_days"]))
        credited = min(approved, Decimal(len(full_scheduled)))
        if bool(row["is_paid"]):
            paid += credited
        else:
            unpaid += credited
    return paid, unpaid


def _assert_payroll_ready(
    connection: Connection,
    *,
    month: date,
) -> None:
    start = _month_start(month)
    end = _month_end(month)
    pending_attendance = connection.execute(
        text(
            """
            SELECT count(*)
            FROM verigence_attendance.attendance_days
            WHERE attendance_date BETWEEN :start AND :end
              AND hr_review_status='PENDING_HR'
            """
        ),
        {"start": start, "end": end},
    ).scalar_one()
    if int(pending_attendance or 0) > 0:
        raise AttendanceRuleError(
            "PAYROLL_ATTENDANCE_REVIEW_PENDING",
            f"{pending_attendance} attendance day(s) still require HR review for this payroll month.",
            status_code=409,
        )

    pending_leave = connection.execute(
        text(
            """
            SELECT count(*)
            FROM verigence_attendance.leave_requests
            WHERE status IN ('PENDING_OPERATIONAL','PENDING_HR')
              AND end_date>=:start
              AND start_date<=:end
            """
        ),
        {"start": start, "end": end},
    ).scalar_one()
    if int(pending_leave or 0) > 0:
        raise AttendanceRuleError(
            "PAYROLL_LEAVE_REVIEW_PENDING",
            f"{pending_leave} leave request(s) still require approval for this payroll month.",
            status_code=409,
        )


def generate_payroll(
    connection: Connection,
    *,
    payroll_month: date,
    actor_user_id: str,
) -> dict[str, object]:
    month = _month_start(payroll_month)
    _assert_payroll_ready(connection, month=month)
    existing = connection.execute(
        text(
            """
            SELECT payroll_run_id,status
            FROM verigence_attendance.payroll_runs
            WHERE payroll_month=:month
            FOR UPDATE
            """
        ),
        {"month": month},
    ).mappings().first()
    if existing is not None and existing["status"] == "FINALIZED":
        raise AttendanceRuleError(
            "PAYROLL_FINALIZED",
            "Finalized payroll cannot be recalculated.",
            status_code=409,
        )
    if existing is None:
        run_id = uuid4()
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.payroll_runs (
                    payroll_run_id,payroll_month,status,generated_by_user_id
                ) VALUES (:run_id,:month,'DRAFT',CAST(:actor AS uuid))
                """
            ),
            {"run_id": run_id, "month": month, "actor": actor_user_id},
        )
    else:
        run_id = UUID(str(existing["payroll_run_id"]))
        connection.execute(
            text(
                "DELETE FROM verigence_attendance.payroll_items "
                "WHERE payroll_run_id=:run_id"
            ),
            {"run_id": run_id},
        )

    employees = [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT employee_id,employee_code,display_name,joining_date,work_location_id
                FROM verigence_attendance.employees
                WHERE employment_status='ACTIVE'
                  AND joining_date<=:month_end
                ORDER BY employee_code
                """
            ),
            {"month_end": _month_end(month)},
        ).mappings()
    ]
    prorate_deductions = bool(
        _config(connection, "payroll.fixed_deductions_prorated", False)
    )

    item_count = 0
    total_net = Decimal(0)
    for employee in employees:
        employee_id = UUID(str(employee["employee_id"]))
        scheduled_list = _scheduled_dates(
            connection,
            month=month,
            joining_date=employee["joining_date"],
            work_location_id=(
                UUID(str(employee["work_location_id"]))
                if employee["work_location_id"] is not None
                else None
            ),
        )
        scheduled = set(scheduled_list)
        scheduled_days = Decimal(len(scheduled))
        if scheduled_days <= 0:
            continue
        present = _present_days(
            connection,
            employee_id=employee_id,
            scheduled=scheduled,
        )
        paid_leave, unpaid_leave = _leave_days(
            connection,
            employee_id=employee_id,
            scheduled=scheduled,
        )
        payable = payable_days(
            scheduled_days=scheduled_days,
            present_days=present,
            paid_leave_days=paid_leave,
            unpaid_leave_days=unpaid_leave,
        ).quantize(_DAY)
        salary = _salary_for_month(connection, employee_id=employee_id, month=month)
        monthly_gross = (
            salary["basic_salary"]
            + salary["hra"]
            + salary["allowances"]
            + salary["other_earnings"]
        )
        ratio = payable / scheduled_days if scheduled_days else Decimal(0)
        basic = _money(salary["basic_salary"] * ratio)
        hra = _money(salary["hra"] * ratio)
        allowances = _money(salary["allowances"] * ratio)
        other_earnings = _money(salary["other_earnings"] * ratio)
        gross = _money(basic + hra + allowances + other_earnings)
        lop_amount = _money(max(Decimal(0), monthly_gross - gross))

        statutory = statutory_config_for_month(connection, month=month)
        profile = payroll_profile_for_month(
            connection,
            employee_id=employee_id,
            month=month,
        )

        pf_employee_rate = Decimal(str(statutory["pf_employee_rate"]))
        pf_employer_rate = Decimal(str(statutory["pf_employer_rate"]))
        pf_ceiling = Decimal(str(statutory["pf_wage_ceiling"]))
        eps_rate = Decimal(str(statutory["eps_employer_rate"]))
        eps_ceiling = Decimal(str(statutory["eps_wage_ceiling"]))
        esi_employee_rate = Decimal(str(statutory["esi_employee_rate"]))
        esi_employer_rate = Decimal(str(statutory["esi_employer_rate"]))
        esi_ceiling = Decimal(str(statutory["esi_wage_ceiling"]))
        gratuity_rate = Decimal(str(statutory["gratuity_provision_rate"]))

        pf_wage = basic
        if not bool(profile["pf_on_actual_wages"]):
            pf_wage = min(pf_wage, pf_ceiling)
        employee_pf = (
            _money(pf_wage * pf_employee_rate)
            if bool(profile["pf_applicable"])
            else Decimal(0)
        )
        employer_pf_total = (
            _money(pf_wage * pf_employer_rate)
            if bool(profile["pf_applicable"])
            else Decimal(0)
        )
        employer_eps = (
            _money(min(basic, eps_ceiling) * eps_rate)
            if bool(profile["pf_applicable"])
            else Decimal(0)
        )
        employer_eps = min(employer_eps, employer_pf_total)
        employer_pf = _money(max(Decimal(0), employer_pf_total - employer_eps))

        esi_eligible = (
            bool(profile["esi_applicable"])
            and monthly_gross <= esi_ceiling
        )
        employee_esi = _money(gross * esi_employee_rate) if esi_eligible else Decimal(0)
        employer_esi = _money(gross * esi_employer_rate) if esi_eligible else Decimal(0)

        professional_tax = _money(Decimal(str(profile["professional_tax_monthly"] or 0)))
        tds_amount = _money(Decimal(str(profile["tds_monthly"] or 0)))
        fixed_deduction = salary["fixed_deductions"]
        other_deductions = _money(
            fixed_deduction * ratio if prorate_deductions else fixed_deduction
        )
        deduction = _money(
            employee_pf
            + employee_esi
            + professional_tax
            + tds_amount
            + other_deductions
        )
        gratuity_provision = (
            _money(basic * gratuity_rate)
            if bool(profile["gratuity_applicable"])
            else Decimal(0)
        )
        employer_cost = _money(
            gross + employer_pf + employer_eps + employer_esi + gratuity_provision
        )
        net = _money(max(Decimal(0), gross - deduction))
        calculation = {
            "monthlyGross": str(_money(monthly_gross)),
            "ratio": str(ratio.quantize(Decimal("0.0001"))),
            "salary": {key: str(_money(value)) for key, value in salary.items()},
            "statutory": {
                "pfEmployeeRate": str(pf_employee_rate),
                "pfEmployerRate": str(pf_employer_rate),
                "pfWageCeiling": str(pf_ceiling),
                "epsEmployerRate": str(eps_rate),
                "epsWageCeiling": str(eps_ceiling),
                "esiEmployeeRate": str(esi_employee_rate),
                "esiEmployerRate": str(esi_employer_rate),
                "esiWageCeiling": str(esi_ceiling),
                "salaryTdsSection": statutory["salary_tds_section"],
            },
            "payrollProfile": {
                "pfApplicable": bool(profile["pf_applicable"]),
                "pfOnActualWages": bool(profile["pf_on_actual_wages"]),
                "esiApplicable": bool(profile["esi_applicable"]),
                "professionalTaxState": profile.get("professional_tax_state"),
                "taxRegime": profile["tax_regime"],
                "gratuityApplicable": bool(profile["gratuity_applicable"]),
            },
            "weeklyOffIsoWeekdays": sorted(_weekly_offs(connection)),
        }
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.payroll_items (
                    payroll_run_id,employee_id,scheduled_days,present_days,
                    paid_leave_days,unpaid_leave_days,payable_days,gross_amount,
                    deduction_amount,net_amount,calculation_json,
                    basic_amount,hra_amount,allowances_amount,other_earnings_amount,
                    lop_amount,employee_pf,employee_esi,professional_tax,tds_amount,
                    other_deductions,employer_pf,employer_eps,employer_esi,
                    gratuity_provision,employer_cost
                ) VALUES (
                    :run_id,:employee_id,:scheduled,:present,:paid_leave,:unpaid_leave,
                    :payable,:gross,:deduction,:net,CAST(:calculation AS jsonb),
                    :basic,:hra,:allowances,:other_earnings,:lop_amount,
                    :employee_pf,:employee_esi,:professional_tax,:tds_amount,
                    :other_deductions,:employer_pf,:employer_eps,:employer_esi,
                    :gratuity_provision,:employer_cost
                )
                """
            ),
            {
                "run_id": run_id,
                "employee_id": employee_id,
                "scheduled": scheduled_days,
                "present": present,
                "paid_leave": paid_leave,
                "unpaid_leave": unpaid_leave,
                "payable": payable,
                "gross": gross,
                "deduction": deduction,
                "net": net,
                "calculation": json.dumps(calculation),
                "basic": basic,
                "hra": hra,
                "allowances": allowances,
                "other_earnings": other_earnings,
                "lop_amount": lop_amount,
                "employee_pf": employee_pf,
                "employee_esi": employee_esi,
                "professional_tax": professional_tax,
                "tds_amount": tds_amount,
                "other_deductions": other_deductions,
                "employer_pf": employer_pf,
                "employer_eps": employer_eps,
                "employer_esi": employer_esi,
                "gratuity_provision": gratuity_provision,
                "employer_cost": employer_cost,
            },
        )
        item_count += 1
        total_net += net

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.payroll_runs
            SET status='CALCULATED',generated_by_user_id=CAST(:actor AS uuid),
                generated_at_utc=now()
            WHERE payroll_run_id=:run_id
            """
        ),
        {"run_id": run_id, "actor": actor_user_id},
    )
    return payroll_summary(connection, run_id)


def payroll_summary(connection: Connection, run_id: UUID) -> dict[str, object]:
    row = connection.execute(
        text(
            """
            SELECT r.payroll_run_id,r.payroll_month,r.status,r.generated_at_utc,
                   r.finalized_at_utc,count(i.payroll_item_id) AS employee_count,
                   COALESCE(sum(i.net_amount),0) AS total_net
            FROM verigence_attendance.payroll_runs r
            LEFT JOIN verigence_attendance.payroll_items i
              ON i.payroll_run_id=r.payroll_run_id
            WHERE r.payroll_run_id=:run_id
            GROUP BY r.payroll_run_id
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    if row is None:
        raise AttendanceNotFoundError("Payroll run not found.")
    return {
        "payrollRunId": row["payroll_run_id"],
        "payrollMonth": row["payroll_month"],
        "status": row["status"],
        "employeeCount": int(row["employee_count"]),
        "totalNetAmount": Decimal(str(row["total_net"])),
        "generatedAtUtc": row["generated_at_utc"],
        "finalizedAtUtc": row["finalized_at_utc"],
    }


def payroll_items(connection: Connection, run_id: UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT i.*,e.employee_code,e.display_name
                FROM verigence_attendance.payroll_items i
                JOIN verigence_attendance.employees e ON e.employee_id=i.employee_id
                WHERE i.payroll_run_id=:run_id
                ORDER BY e.employee_code
                """
            ),
            {"run_id": run_id},
        ).mappings()
    ]


def finalize_payroll(
    connection: Connection,
    *,
    run_id: UUID,
    actor_user_id: str,
    storage: AttendanceStorage,
) -> dict[str, object]:
    run = connection.execute(
        text(
            """
            SELECT payroll_run_id,payroll_month,status
            FROM verigence_attendance.payroll_runs
            WHERE payroll_run_id=:run_id
            FOR UPDATE
            """
        ),
        {"run_id": run_id},
    ).mappings().first()
    if run is None:
        raise AttendanceNotFoundError("Payroll run not found.")
    if run["status"] == "FINALIZED":
        return payroll_summary(connection, run_id)
    if run["status"] != "CALCULATED":
        raise AttendanceRuleError(
            "PAYROLL_STATE_INVALID",
            "Payroll must be calculated before finalization.",
        )

    for item in payroll_items(connection, run_id):
        lines = [
            "VERIGENCE - PAYSLIP",
            f"Payroll Month: {run['payroll_month']:%B %Y}",
            f"Employee: {item['display_name']} ({item['employee_code']})",
            "",
            f"Scheduled Days: {item['scheduled_days']}",
            f"Present Days: {item['present_days']}",
            f"Paid Leave Days: {item['paid_leave_days']}",
            f"Unpaid Leave Days: {item['unpaid_leave_days']}",
            f"Payable Days: {item['payable_days']}",
            "",
            "EARNINGS",
            f"Basic: INR {item['basic_amount']}",
            f"HRA: INR {item['hra_amount']}",
            f"Allowances: INR {item['allowances_amount']}",
            f"Other Earnings: INR {item['other_earnings_amount']}",
            f"Gross Pay: INR {item['gross_amount']}",
            f"LOP Impact: INR {item['lop_amount']}",
            "",
            "DEDUCTIONS",
            f"Employee PF: INR {item['employee_pf']}",
            f"Employee ESI: INR {item['employee_esi']}",
            f"Professional Tax: INR {item['professional_tax']}",
            f"TDS: INR {item['tds_amount']}",
            f"Other Deductions: INR {item['other_deductions']}",
            f"Total Deductions: INR {item['deduction_amount']}",
            f"Net Pay: INR {item['net_amount']}",
            "",
            "EMPLOYER CONTRIBUTIONS / PROVISIONS",
            f"Employer PF: INR {item['employer_pf']}",
            f"Employer EPS: INR {item['employer_eps']}",
            f"Employer ESI: INR {item['employer_esi']}",
            f"Gratuity Provision: INR {item['gratuity_provision']}",
            f"Employer Cost: INR {item['employer_cost']}",
            "",
            "System-generated payslip.",
        ]
        pdf = simple_text_pdf(lines)
        payslip_id = uuid4()
        object_key = (
            f"employee-payslips/{item['employee_id']}/"
            f"{run['payroll_month'].isoformat()}/{payslip_id}.pdf"
        )
        try:
            storage.put(
                object_key=object_key,
                data=pdf,
                content_type="application/pdf",
            )
        except AttendanceStorageError as exc:
            raise AttendanceRuleError(
                "PAYSLIP_STORAGE_UNAVAILABLE",
                "Could not store generated payslips. Payroll was not finalized.",
                status_code=503,
            ) from exc
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.payslips (
                    payslip_id,payroll_item_id,employee_id,pdf_object_key,pdf_sha256
                ) VALUES (
                    :payslip_id,:item_id,:employee_id,:object_key,:sha256
                )
                ON CONFLICT (payroll_item_id) DO NOTHING
                """
            ),
            {
                "payslip_id": payslip_id,
                "item_id": item["payroll_item_id"],
                "employee_id": item["employee_id"],
                "object_key": object_key,
                "sha256": hashlib.sha256(pdf).hexdigest(),
            },
        )

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.payroll_runs
            SET status='FINALIZED',finalized_by_user_id=CAST(:actor AS uuid),
                finalized_at_utc=now()
            WHERE payroll_run_id=:run_id
            """
        ),
        {"run_id": run_id, "actor": actor_user_id},
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.approval_actions (
                entity_type,entity_id,stage,decision,actor_user_id,actor_role
            ) VALUES (
                'PAYROLL',:run_id,'FINAL','FINALIZE',CAST(:actor AS uuid),'HRADMIN'
            )
            """
        ),
        {"run_id": run_id, "actor": actor_user_id},
    )
    return payroll_summary(connection, run_id)
