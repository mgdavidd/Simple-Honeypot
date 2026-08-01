import os
from config import TEMPLATE

# ── Campos de credenciales por template ───────────────────────────────────────
_LOGIN_FIELDS: dict[str, dict] = {
    "wordpress": {
        "username_fields": ["log", "user", "username", "email"],
        "password_fields": ["pwd", "password", "pass"],
    },
    "xampp": {
        "username_fields": ["username", "user", "login"],
        "password_fields": ["password", "pass", "pwd"],
    },
}

_DEFAULT_FIELDS: dict = {
    "username_fields": ["username", "user", "login", "log", "email"],
    "password_fields": ["password", "pass", "pwd"],
}

_DASHBOARD_MAP: dict[str, str] = {
    "wordpress": "dashboard_wordpress",
    "xampp":     "dashboard_xampp",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_template(name: str) -> str:
    path = os.path.join(os.path.dirname(__file__), f"templates/{name}.html")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return f"<h1>Error: Template '{name}' not found</h1>"


def get_login_template() -> str:
    return load_template(TEMPLATE)


def get_dashboard_template() -> str:
    return load_template(_DASHBOARD_MAP.get(TEMPLATE, "dashboard_wordpress"))


def get_login_fields() -> dict:
    return _LOGIN_FIELDS.get(TEMPLATE, _DEFAULT_FIELDS)