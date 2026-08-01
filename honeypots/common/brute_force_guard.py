import threading
import os
from datetime import datetime

from .log_client import send_bruteforce_alert
from .ip_blocker import IPBlocker


class BruteForceGuard:
    """
    Cuenta intentos de autenticación acumulados por IP (sin importar
    sesión, puerto, ni si los intentos fueron consecutivos). Al llegar
    al umbral, emite un log tipo "ssh_brute_force" con la lista de
    credenciales usadas y bloquea la IP temporalmente.
    """

    FAILED_THRESHOLD = int(os.getenv("CONFIG_FAILED_THRESHOLD", 20))
    BAN_SECONDS = int(os.getenv("CONFIG_BAN_SECONDS", 600))

    def __init__(self, service_id: str = None, blocker: IPBlocker = None):
        self.service_id = service_id
        if not self.service_id:
            SERVICE_TYPE = os.getenv("SERVICE_TYPE", "ssh")
            REPLICA_ID = os.getenv("REPLICA_ID", "1")
            self.service_id = f"{SERVICE_TYPE}-{REPLICA_ID}"
        
        self._lock = threading.Lock()
        self._attempts_by_ip = {}
        self._triggered_ips = set()
        self.blocker = blocker or IPBlocker()

    def record_attempt(self, ip, username, password, invalid=False):
        with self._lock:
            if ip in self._triggered_ips:
                return

            attempts = self._attempts_by_ip.setdefault(ip, [])
            if invalid:
                attempts.append({"username": username, "invalid_user": True})
            else:
                attempts.append({"username": username, "password": password})

            if len(attempts) >= self.FAILED_THRESHOLD:
                self._trigger(ip, list(attempts))

    def _trigger(self, ip, attempts):
        self._triggered_ips.add(ip)

        send_bruteforce_alert(
            service_id=self.service_id,
            ip=ip,
            total_attempts=len(attempts),
            credentials_tried=attempts,
            action=f"blocked_{self.BAN_SECONDS}s",
            detected_at=datetime.now().isoformat()
        )

        print(f"[brute-force] ({self.service_id}) Umbral alcanzado para {ip}: {len(attempts)} intentos. Bloqueando {self.BAN_SECONDS}s.")
        self.blocker.block(ip, seconds=self.BAN_SECONDS, on_unblock=lambda: self._reset(ip))

    def _reset(self, ip):
        with self._lock:
            self._triggered_ips.discard(ip)
            self._attempts_by_ip.pop(ip, None)
        print(f"[brute-force] ({self.service_id}) {ip} desbloqueada, contador reiniciado.")