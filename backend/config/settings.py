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

    @model_validator(mode="after")
    def validate_required_services(self) -> "Settings":
        """
        In normal mode, Supabase settings are required.
        In offline mode, the backend runs with an in-memory store and does not
        require Supabase connectivity.
        """
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
