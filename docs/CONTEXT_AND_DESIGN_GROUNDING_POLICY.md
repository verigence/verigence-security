# Verigence Security — Context and Design-Grounding Policy

**Purpose:** Mandatory execution rule for implementation, review and context recovery.

## Core rule

Verigence Security implementation must be built from the approved Security design documents and approved decision artifacts. The design is the reference; implementation extends that baseline only where an explicit, approved decision permits it.

**No hallucination / no assumption rule:**

- Do not invent APIs, fields, permission names, error codes, statuses, database objects, thresholds, provider behavior, lifecycle states or security rules merely to make code compile or tests pass.
- Do not silently reinterpret an approved requirement because a framework default behaves differently.
- Do not silently modify a v1.3 normative artifact to fit implementation.
- If the design does not deterministically answer an implementation question, mark the item `BLOCKED`, `PARTIAL` or `OPEN DESIGN DECISION`; document the gap before coding the missing behavior.
- Engineering choices are allowed only inside boundaries left open by the design and must not be represented as approved business/security requirements.
- Every material implementation increment must be reviewed against the applicable approved design/decision documents before it is marked DONE or merged into `dev`.

## Source priority after a context reset

Read sources in this order before changing code:

1. Approved Security v1.3 source reference/checksums in `docs/APPROVED_SOURCE_REFERENCE.md`.
2. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
3. `docs/SECURITY_CORRELATION_STANDARD_v1.3.md`.
4. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
5. Applicable approved OpenAPI/schema artifact referenced by the v1.3 source manifest.
6. `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.
7. `docs/IMPLEMENTATION_STATUS.md`.
8. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
9. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
10. Current code and tests.
11. Chat history only as supporting context, never as a replacement for the approved design.

## Implementation evidence rule

A capability is marked DONE only when all applicable conditions are true:

- the design requirement is identifiable;
- code implements that requirement without adding unapproved behavior;
- automated tests cover the implemented contract;
- static/design-integrity gates pass where applicable;
- infrastructure validation is completed where required by the milestone;
- the progress tracker/status document is updated with evidence.

## Handling ambiguity

When a question is not covered by the approved sources:

1. Record the exact gap.
2. Explain why existing design text does not resolve it.
3. Do not choose a business/security behavior by convenience.
4. Obtain and record an explicit decision.
5. Version the design/decision artifact when the decision changes the approved baseline.
6. Implement only after the decision is recorded.

This policy is intentionally stricter than ordinary implementation practice because Security is a platform control boundary. Convenience is not a valid reason to create an undocumented security contract.
