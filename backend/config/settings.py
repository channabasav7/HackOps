from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from pydantic import field_validator
from pydantic import model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    sentinel_offline_mode: bool = False
    sentinel_env: str = "development"

    supabase_db_url: str | None = None
    supabase_url: str | None = None
    supabase_service_role_key: str | None = None

    aes_master_key: str  # 64-char hex string → 32 bytes
    hmac_secret: str

    bloom_filter_size: int = 10_000
    bloom_hash_count: int = 7
    threat_match_threshold: int = 2

    jwt_secret: str = "change-me-in-production-sentinel-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours

    cors_origins: str | None = None
    cors_allow_origin_regex: str | None = r"https://.*\.vercel\.app"

    auth_rate_limit_max_attempts: int = 5
    auth_rate_limit_window_seconds: int = 60

    @field_validator("aes_master_key")
    @classmethod
    def validate_aes_master_key(cls, v: str) -> str:
        key = v.strip()
        if len(key) != 64:
            raise ValueError("AES_MASTER_KEY must be a 64-char hex string (32 bytes).")
        try:
            bytes.fromhex(key)
        except ValueError as exc:
            raise ValueError("AES_MASTER_KEY must contain only hexadecimal characters.") from exc
        return key

    @field_validator("hmac_secret")
    @classmethod
    def validate_hmac_secret(cls, v: str) -> str:
        secret = v.strip()
        if not secret or "replace-me" in secret.lower():
            raise ValueError("HMAC_SECRET is missing or still a placeholder.")
        return secret

    @field_validator("sentinel_env")
    @classmethod
    def validate_sentinel_env(cls, v: str) -> str:
        env = v.strip().lower()
        allowed = {"development", "staging", "production"}
        if env not in allowed:
            raise ValueError("SENTINEL_ENV must be one of: development, staging, production.")
        return env

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        secret = v.strip()
        if len(secret) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters.")
        lowered = secret.lower()
        weak_markers = ("change-me", "your_", "placeholder")
        if any(marker in lowered for marker in weak_markers):
            raise ValueError("JWT_SECRET appears to be a placeholder; set a strong random secret.")
        return secret

    @field_validator("auth_rate_limit_max_attempts", "auth_rate_limit_window_seconds")
    @classmethod
    def validate_positive_ints(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Rate-limit settings must be >= 1.")
        return v

    def get_cors_origins(self, default: list[str] | None = None) -> list[str]:
        if self.cors_origins:
            return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        return list(default or [])

    @model_validator(mode="after")
    def validate_required_services(self) -> "Settings":
        """
        In normal mode, Supabase settings are required.
        In offline mode, the backend runs with an in-memory store and does not
        require Supabase connectivity.
        """
        if self.sentinel_env == "production" and not self.cors_origins:
            raise ValueError("CORS_ORIGINS must be explicitly set in production.")

        if self.sentinel_offline_mode:
            return self

        missing = []
        if not (self.supabase_db_url and self.supabase_db_url.strip()):
            missing.append("SUPABASE_DB_URL")
        if not (self.supabase_url and self.supabase_url.strip()):
            missing.append("SUPABASE_URL")
        if not (self.supabase_service_role_key and self.supabase_service_role_key.strip()):
            missing.append("SUPABASE_SERVICE_ROLE_KEY")
        if missing:
            raise ValueError(
                "Missing required environment variables: " + ", ".join(missing) + ". "
                "Either configure Supabase credentials, or set SENTINEL_OFFLINE_MODE=true."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
