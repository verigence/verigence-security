from __future__ import annotations

from uuid import UUID

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.runtime_service import RuntimeAttendanceService
from verigence_security.attendance.schemas import AttendanceWorkContext, OutletContext

TENANT_ID = UUID("00000000-0000-4000-8000-000000000201")
USER_ID = UUID("00000000-0000-4000-8000-000000000101")
DEALER_ID = UUID("00000000-0000-4000-8000-000000000301")
OUTLET_ID = UUID("00000000-0000-4000-8000-000000000401")


class _AuditCore:
    def __init__(self, context: AttendanceWorkContext | None) -> None:
        self.context = context
        self.calls = 0

    def current_work_context(
        self,
        *,
        tenant_id: UUID,
        human_bearer_token: str,
    ) -> AttendanceWorkContext | None:
        assert tenant_id == TENANT_ID
        assert human_bearer_token == "human-token"
        self.calls += 1
        return self.context


def _service(audit_core: _AuditCore) -> RuntimeAttendanceService:
    return RuntimeAttendanceService(
        repository=object(),  # type: ignore[arg-type]
        settings=AttendanceSettings(),
        security=object(),  # type: ignore[arg-type]
        audit_core=audit_core,  # type: ignore[arg-type]
    )


def test_tl_operating_action_does_not_call_audit_core() -> None:
    audit_core = _AuditCore(None)
    context = _service(audit_core)._work_context_for_action(
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        human_bearer_token="human-token",
        authorization={"classification": "Operating", "roleKey": "TL"},
    )

    assert audit_core.calls == 0
    assert context.operatingRole == "TL"
    assert context.geofenceRequired is False
    assert context.outlets == []


def test_pm_operating_action_does_not_call_audit_core() -> None:
    audit_core = _AuditCore(None)
    context = _service(audit_core)._work_context_for_action(
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        human_bearer_token="human-token",
        authorization={"classification": "Operating", "roleKey": "PM"},
    )

    assert audit_core.calls == 0
    assert context.operatingRole == "PM"
    assert context.geofenceRequired is False


def test_pc_operating_action_requires_audit_core_geofence_context() -> None:
    expected = AttendanceWorkContext(
        userId=USER_ID,
        operatingRole="PC",
        geofenceRequired=True,
        outlets=[
            OutletContext(
                dealerId=DEALER_ID,
                outletId=OUTLET_ID,
                outletName="Assigned Outlet",
                latitude=20.2961,
                longitude=85.8245,
            )
        ],
    )
    audit_core = _AuditCore(expected)
    context = _service(audit_core)._work_context_for_action(
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        human_bearer_token="human-token",
        authorization={"classification": "Operating", "roleKey": "PC"},
    )

    assert audit_core.calls == 1
    assert context == expected


def test_hradmin_secondary_role_can_coexist_with_underlying_pc() -> None:
    expected = AttendanceWorkContext(
        userId=USER_ID,
        operatingRole="PC",
        geofenceRequired=True,
        outlets=[],
    )
    audit_core = _AuditCore(expected)
    context = _service(audit_core)._work_context_for_action(
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        human_bearer_token="human-token",
        authorization={"classification": "Module", "roleKey": "HRADMIN"},
    )

    assert audit_core.calls == 1
    assert context.operatingRole == "PC"
    assert context.geofenceRequired is True


def test_hradmin_without_operating_assignment_remains_non_geofenced() -> None:
    audit_core = _AuditCore(None)
    context = _service(audit_core)._work_context_for_action(
        tenant_id=TENANT_ID,
        user_id=USER_ID,
        human_bearer_token="human-token",
        authorization={"classification": "Module", "roleKey": "HRADMIN"},
    )

    assert audit_core.calls == 1
    assert context.operatingRole == "HRADMIN"
    assert context.geofenceRequired is False
    assert context.outlets == []


def test_attendance_cors_adds_only_approved_native_origins() -> None:
    settings = AttendanceSettings(
        allowed_origins="https://verigence-web-dev.example,capacitor://localhost"
    )

    assert settings.allowed_origin_list == [
        "https://verigence-web-dev.example",
        "capacitor://localhost",
        "https://localhost",
    ]
