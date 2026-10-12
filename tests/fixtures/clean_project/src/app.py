"""A small app that handles configuration correctly. Must scan clean."""

import hashlib
import os

DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.getenv("API_KEY", "")
REDIS_URL = "redis://localhost:6379/0"
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"
LAST_COMMIT = "9fceb02d0ae598e95dc970b74767f19372d61af8"
DOCS_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # the documented AWS example key
TOKEN_HEADER = "X-Auth-Token"
password_prompt = "Enter your password: "


class UserAccountSettingsRepositoryFactory:
    """Long identifiers are not secrets."""

    def build(self, user_id: int) -> dict:
        return {"user": user_id, "token_ttl_seconds": 3600}


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def connect(password: str) -> str:
    return f"postgres://app:{password}@db.internal/app"
