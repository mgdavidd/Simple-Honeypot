from config import VALID_CREDENTIALS


def extract_credentials(form_data: dict, login_fields: dict) -> tuple[str | None, str | None]:
    """Extrae username y password del formulario según los campos configurados."""
    username = next(
        (form_data[f] for f in login_fields.get("username_fields", []) if f in form_data),
        None,
    )
    password = next(
        (form_data[f] for f in login_fields.get("password_fields", []) if f in form_data),
        None,
    )
    return username, password


def is_login_attempt(form_data: dict, login_fields: dict) -> bool:
    """Devuelve True si el POST contiene algún campo de login conocido."""
    fields = login_fields.get("username_fields", []) + login_fields.get("password_fields", [])
    return any(f in form_data for f in fields)


def validate_credentials(username: str | None, password: str | None) -> bool:
    """Valida las credenciales contra las configuradas en el entorno."""
    if not VALID_CREDENTIALS:
        return False
    return (
        VALID_CREDENTIALS.get("username") == username
        and VALID_CREDENTIALS.get("password") == password
    )