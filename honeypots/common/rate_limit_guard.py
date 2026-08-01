import threading
import time
from collections import defaultdict
import os
from datetime import datetime

from .ip_blocker import IPBlocker
from .log_client import send_log


class RateLimitGuard:
    def __init__(self, service_id: str, blocker: IPBlocker = None):
        if not service_id:
            raise ValueError("service_id es requerido")
        self.service_id = service_id
        self._lock = threading.Lock()
        self._request_history = defaultdict(list)
        self._triggered_ips = set()
        self.blocker = blocker or IPBlocker()
        # Leer desde variables de entorno (con defaults)
        self.WINDOW_SECONDS = int(os.getenv("CONFIG_RATE_LIMIT_WINDOW", "15"))
        self.REQUEST_THRESHOLD = int(os.getenv("CONFIG_RATE_LIMIT_THRESHOLD", "30"))
        self.BAN_SECONDS = int(os.getenv("CONFIG_BAN_SECONDS", "600"))

    def record_request(self, ip: str):
        with self._lock:
            if ip in self._triggered_ips:
                return
            now = time.time()
            self._request_history[ip].append(now)
            # Limpiar peticiones fuera de ventana
            self._request_history[ip] = [
                t for t in self._request_history[ip]
                if now - t < self.WINDOW_SECONDS
            ]
            count = len(self._request_history[ip])
            if count >= self.REQUEST_THRESHOLD:
                self._trigger(ip, count)

    def _trigger(self, ip: str, count: int):
        self._triggered_ips.add(ip)
        # Enviar log de rate limit como alerta de fuerza bruta
        send_log(
            service_id=self.service_id,
            data={
                "ip": ip,
                "total_attempts": count,
                "credentials_tried": [],
                "action": f"rate_limit_blocked_{self.BAN_SECONDS}s",
                "detected_at": datetime.now().isoformat()
            }
        )
        print(f"[rate-limit] {self.service_id}: {ip} bloqueada por rate limit ({count} GETs en {self.WINDOW_SECONDS}s)")
        self.blocker.block(
            ip,
            seconds=self.BAN_SECONDS,
            on_unblock=lambda: self._reset(ip)
        )

    def _reset(self, ip: str):
        with self._lock:
            self._triggered_ips.discard(ip)
            self._request_history.pop(ip, None)
        print(f"[rate-limit] {self.service_id} | {ip} desbloqueada")