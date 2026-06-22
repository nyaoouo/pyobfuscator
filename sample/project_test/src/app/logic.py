"""Business logic — PLAINTEXT, meant for users to read and modify. It reverse-imports the protected
``app.secret`` module (which the entry's shared runtime decrypts on import)."""
from app.secret import license_ok, core_transform


def run(key, payload):
    if not license_ok(key):
        return "DENIED"
    return "OK:" + core_transform(payload)
