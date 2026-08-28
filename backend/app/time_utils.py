from datetime import datetime
from zoneinfo import ZoneInfo

COLOMBIA_TZ = ZoneInfo("America/Bogota")


def colombia_now() -> datetime:
    return datetime.now(COLOMBIA_TZ)
