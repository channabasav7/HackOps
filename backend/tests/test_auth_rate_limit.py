import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.auth import reset_auth_rate_limiter_for_tests, router as auth_router
from config.settings import get_settings


def _configure_env() -> None:
    os.environ["SENTINEL_OFFLINE_MODE"] = "true"
    os.environ["AES_MASTER_KEY"] = "a" * 64
    os.environ["HMAC_SECRET"] = "sentinel-hmac-secret"
    os.environ["JWT_SECRET"] = "s" * 32
    os.environ["AUTH_RATE_LIMIT_MAX_ATTEMPTS"] = "2"
    os.environ["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "120"



def test_login_rate_limit_blocks_after_repeated_failures() -> None:
    _configure_env()
    get_settings.cache_clear()
    reset_auth_rate_limiter_for_tests()

    app = FastAPI()
    app.include_router(auth_router)
    client = TestClient(app)

    payload = {
        "uuid": "550e8400-e29b-41d4-a716-446655440001",
        "password": "wrong-password",
    }

    response_1 = client.post("/api/auth/login", json=payload)
    response_2 = client.post("/api/auth/login", json=payload)
    response_3 = client.post("/api/auth/login", json=payload)

    assert response_1.status_code == 401
    assert response_2.status_code == 401
    assert response_3.status_code == 429
    assert "Retry-After" in response_3.headers
