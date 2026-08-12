# Verigence Correlation-ID Standard v1.3

## 1. Header
Canonical header: `X-Correlation-ID`.

## 2. Inbound behavior
- A caller MAY supply `X-Correlation-ID`.
- Accepted caller-supplied values are opaque safe strings of 1-128 characters matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.
- If the value is absent, the first Verigence service handling the request MUST generate a UUIDv4 string.
- If a supplied value is syntactically invalid, return HTTP 400 with `CORRELATION_ID_INVALID`; do not silently normalize it.

## 3. Response behavior
Every Verigence HTTP response, success or error, MUST include `X-Correlation-ID` with the resolved value for that request.

## 4. Propagation
- Internal synchronous calls MUST propagate the same `X-Correlation-ID` unchanged.
- SYSTEM and SERVICE_INTEGRATION calls use the same contract.
- Provider adapters SHOULD pass the same header when the provider supports arbitrary correlation headers. If not supported, the adapter MUST log/store the Verigence correlation ID alongside the provider request/reference ID.
- No downstream service may replace an existing correlation ID with a new value.

## 5. Scheduled/background work
A scheduled task or independently started background operation with no inbound request MUST generate a new UUIDv4 correlation ID at execution start and use it through that processing chain.

## 6. Storage and observability
The correlation ID MUST be present in structured logs and in Security evidence/events where the schema has `correlation_id`, including `access_context_evaluations` and `security_events`.

## 7. Relationship to distributed tracing
`X-Correlation-ID` is the stable business/request-chain correlation token. It does not prevent future adoption of W3C `traceparent`/OpenTelemetry trace/span identifiers. If tracing is later added, both may coexist; this correlation contract remains stable.
