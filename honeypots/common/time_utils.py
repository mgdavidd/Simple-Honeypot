from datetime import datetime, timezone, timedelta

try:
    from zoneinfo import ZoneInfo
    COLOMBIA_TZ = ZoneInfo("America/Bogota")
    _USE_ZONEINFO = True
except Exception:
    # Fallback cuando tzdata no está instalado en el contenedor.
    # Colombia es UTC-5 todo el año (no usa horario de verano).
    COLOMBIA_TZ = None
    _USE_ZONEINFO = False

_COLOMBIA_OFFSET = timezone(timedelta(hours=-5))


def colombia_now() -> datetime:
    if _USE_ZONEINFO and COLOMBIA_TZ is not None:
        return datetime.now(COLOMBIA_TZ)
    return datetime.now(_COLOMBIA_OFFSET)