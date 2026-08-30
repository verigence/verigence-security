from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_CAPACITOR_ORIGINS = ("capacitor://localhost", "https://localhost")


class AttendanceSettings(BaseSettings):
    """Configuration owned by the isolated Attendance runtime.

    All variables are ATTENDANCE_* so deploying this service does not change the
    existing Security process configuration.
    """

    model_config = SettingsConfigDict(
        env_prefix="ATTENDANCE_",
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "verigence-attendance"
    environment: str = "DEV"
    database_url: str = ""

    security_base_url: str = ""
    security_client_id: str = ""
    security_client_secret: str = ""
    security_public_key_pem: str = ""
    security_token_issuer: str = "verigence-security"
    security_token_audience: str = "verigence-platform"

    audit_core_base_url: str = ""
    downstream_timeout_seconds: float = Field(default=1.5, gt=0.1, le=5.0)

    default_timezone: str = "Asia/Kolkata"
    default_pc_geofence_radius_m: int = Field(default=300, ge=50, le=5000)
    default_max_location_accuracy_m: float = Field(default=150.0, gt=0, le=5000)
    default_max_location_age_seconds: int = Field(default=120, ge=10, le=900)

    reverse_geocode_base_url: str = "https://nominatim.openstreetmap.org"
    reverse_geocode_timeout_seconds: float = Field(default=2.5, gt=0.5, le=5.0)
    reverse_geocode_user_agent: str = "VerigenceAttendance/0.1 (DEV reverse geocoding)"

    db_pool_size: int = Field(default=5, ge=1, le=20)
    db_max_overflow: int = Field(default=5, ge=0, le=20)
    db_pool_timeout_seconds: int = Field(default=2, ge=1, le=10)

    allowed_origins: str = ""

    @field_validator("security_public_key_pem", mode="before")
    @classmethod
    def normalize_public_key(cls, value: object) -> object:
        if isinstance(value, str):
            return value.replace("\\n", "\n")
        return value

    @property
    def allowed_origin_list(self) -> list[str]:
        configured = [
            value.strip()
            for value in self.allowed_origins.split(",")
            if value.strip()
        ]
        # The native Verigence app uses these stable Capacitor/WebView origins. Keep
        # them local to the isolated Attendance runtime so native attendance works
        # without widening CORS on Security, Audit Core, DI, or normal Web traffic.
        return list(dict.fromkeys([*configured, *_CAPACITOR_ORIGINS]))


@lru_cache
def get_attendance_settings() -> AttendanceSettings:
    return AttendanceSettings()
