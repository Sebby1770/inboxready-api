from __future__ import annotations

import hashlib
import secrets


def hash_password(password: str, *, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False

    try:
        algorithm, raw_iterations, salt_hex, digest_hex = encoded.split("$", maxsplit=3)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    try:
        iterations = int(raw_iterations)
        if not 100_000 <= iterations <= 1_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (TypeError, ValueError):
        return False
    if len(salt) != 16 or len(expected) != 32:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return secrets.compare_digest(actual, expected)


def validate_password(password: str) -> None:
    value = password.strip()
    if value != password:
        raise ValueError("Password must not start or end with whitespace.")
    if len(value) < 10:
        raise ValueError("Password must be at least 10 characters.")
    if value.lower() == value or value.upper() == value:
        raise ValueError("Password should mix uppercase and lowercase letters.")
    if not any(character.isdigit() for character in value):
        raise ValueError("Password must include at least one number.")
