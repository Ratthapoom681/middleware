"""
Helpers for startup diagnostics.
"""

from urllib.parse import urlsplit, urlunsplit


def redact_database_url(url: str) -> str:
    """Hide passwords before logging a database URL."""
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return url

    hostname = parsed.hostname or ""
    if parsed.username:
        auth = parsed.username
        if parsed.password is not None:
            auth += ":***"
        netloc = f"{auth}@{hostname}"
    else:
        netloc = hostname

    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def build_database_startup_error(url: str, exc: Exception) -> str:
    """Return an actionable startup error for database connection failures."""
    safe_url = redact_database_url(url)
    prefix = f"Database startup failed for {safe_url}."

    if exc.__class__.__name__ == "InvalidPasswordError":
        return (
            f"{prefix} PostgreSQL rejected the configured username/password. "
            "If you are using the bundled Docker Compose stack, make sure the "
            "`postgres` and `middleware` services share the same POSTGRES_* "
            "credentials. If POSTGRES_PASSWORD changed after the postgres data "
            "volume was created, either reset it with `docker compose down -v` "
            "or update the role password inside PostgreSQL."
        )

    return f"{prefix} {exc.__class__.__name__}: {exc}"
