import os
from config import TEMPLATE

# ── Campos de credenciales por template ───────────────────────────────────────
_LOGIN_FIELDS: dict[str, dict] = {
    "wordpress": {
        "username_fields": ["log", "user", "username", "email"],
        "password_fields": ["pwd", "password", "pass"],
    },
    "phpmyadmin": {
        "username_fields": ["pma_username", "username", "user"],
        "password_fields": ["pma_password", "password", "pass"],
    },
    # Alias legacy
    "xampp": {
        "username_fields": ["username", "user", "login"],
        "password_fields": ["password", "pass", "pwd"],
    },
}

_DEFAULT_FIELDS: dict = {
    "username_fields": ["username", "user", "login", "log", "email", "pma_username"],
    "password_fields": ["password", "pass", "pwd", "pma_password"],
}


def get_login_fields() -> dict:
    return _LOGIN_FIELDS.get(TEMPLATE, _DEFAULT_FIELDS)