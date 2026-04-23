"""
Tests for startup diagnostics in the root FastAPI entry point.
"""

from main import _build_database_startup_error, _redact_database_url


class InvalidPasswordError(Exception):
    """Local stand-in for asyncpg's auth error."""


def test_redact_database_url_masks_password():
    assert _redact_database_url(
        "postgresql://middleware:middleware_secret@postgres:5432/middleware"
    ) == "postgresql://middleware:***@postgres:5432/middleware"


def test_build_database_startup_error_explains_stale_volume():
    message = _build_database_startup_error(
        "postgresql://middleware:middleware_secret@postgres:5432/middleware",
        InvalidPasswordError('password authentication failed for user "middleware"'),
    )

    assert "PostgreSQL rejected the configured username/password" in message
    assert "docker compose down -v" in message
    assert "middleware_secret" not in message
