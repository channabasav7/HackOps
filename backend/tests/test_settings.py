from pydantic import ValidationError

from config.settings import Settings


def build_settings(**overrides):
    base = {
        "sentinel_offline_mode": True,
        "aes_master_key": "a" * 64,
        "hmac_secret": "sentinel-hmac-secret",
        "jwt_secret": "s" * 32,
    }
    base.update(overrides)
    return Settings(**base)


def test_rejects_weak_jwt_secret() -> None:
    try:
        build_settings(jwt_secret="too-short")
        assert False, "Expected ValidationError for weak JWT secret"
    except ValidationError as exc:
        assert "JWT_SECRET" in str(exc)


def test_requires_explicit_cors_origins_in_production() -> None:
    try:
        build_settings(sentinel_env="production", cors_origins=None)
        assert False, "Expected ValidationError for missing CORS_ORIGINS in production"
    except ValidationError as exc:
        assert "CORS_ORIGINS" in str(exc)


def test_parses_comma_delimited_cors_origins() -> None:
    settings = build_settings(cors_origins="http://localhost:3000, http://127.0.0.1:3000")
    assert settings.get_cors_origins() == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
