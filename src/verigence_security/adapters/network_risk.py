from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from verigence_security.core.types import VpnStatus


@dataclass(frozen=True, slots=True)
class NetworkRiskResult:
    vpn_status: VpnStatus
    risk_reasons: tuple[str, ...] = ()
    provider_reference: str | None = None


class NetworkRiskAdapter(Protocol):
    def evaluate(self, source_ip: str, correlation_id: str) -> NetworkRiskResult: ...


class MockNetworkRiskAdapter:
    def __init__(self, status: VpnStatus) -> None:
        self._status = status

    def evaluate(self, source_ip: str, correlation_id: str) -> NetworkRiskResult:
        _ = source_ip, correlation_id
        return NetworkRiskResult(self._status, ("DEV_MOCK",))


class UnknownNetworkRiskAdapter:
    """Safe provider-neutral fallback: no network/VPN detection claim is made."""

    def evaluate(self, source_ip: str, correlation_id: str) -> NetworkRiskResult:
        _ = source_ip, correlation_id
        return NetworkRiskResult(VpnStatus.UNKNOWN, ("PROVIDER_NOT_CONFIGURED",))
