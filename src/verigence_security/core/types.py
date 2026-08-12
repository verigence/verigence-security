from __future__ import annotations

from enum import StrEnum


class AppEnvironment(StrEnum):
    LOCAL = "local"
    CI = "ci"
    DEV = "dev"
    UAT = "uat"
    PRODUCTION = "production"


class ActorType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    SERVICE_INTEGRATION = "SERVICE_INTEGRATION"


class GeoSource(StrEnum):
    NATIVE = "NATIVE"
    BROWSER = "BROWSER"


class GeoIntegrityStatus(StrEnum):
    NORMAL = "NORMAL"
    SUSPECTED = "SUSPECTED"
    UNKNOWN = "UNKNOWN"


class VpnStatus(StrEnum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    UNKNOWN = "UNKNOWN"


class PolicyAction(StrEnum):
    DENY = "DENY"
    FLAG = "FLAG"
