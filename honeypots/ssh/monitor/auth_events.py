import os
import time
import threading

AUTH_LOG_PATH = "/var/log/honeypot/auth_events.log"


class AuthEventsWatcher:
    """
    Sigue el archivo que llena capture_auth.sh (PAM) con la contraseña
    real intentada. Es la ÚNICA fuente de credenciales del sistema.
    """

    def __init__(self, on_password_captured, path=AUTH_LOG_PATH):
        self.on_password_captured = on_password_captured
        self.path = path

    def start(self):
        self._ensure_log_file()
        threading.Thread(target=self._watch_loop, daemon=True).start()

    def _ensure_log_file(self):
        """
        Crea el archivo de log si no existe y anota si ya existía.
        """
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._file_preexisted = os.path.exists(self.path)
        if not self._file_preexisted:

            open(self.path, "a").close()
            print(f"[AuthEventsWatcher] Archivo de log creado: {self.path}")
        else:
            print(f"[AuthEventsWatcher] Archivo de log ya existía: {self.path}")

    def _watch_loop(self):
        with open(self.path, "r") as f:
            if self._file_preexisted:
                f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                threading.Thread(
                    target=self._deliver,
                    args=(line,),
                    daemon=True,
                ).start()

    def _deliver(self, line):
        parts = line.rstrip("\n").split("\t", 4)
        if len(parts) < 4 or parts[0] != "AUTH":
            return

        _, _timestamp, username, ip = parts[0], parts[1], parts[2], parts[3]
        password = parts[4].strip() if len(parts) > 4 else ""

        if not username or username == "unknown":
            return
        if not ip or ip == "unknown":
            return

        password = "".join(c for c in password if c.isprintable())

        self.on_password_captured(ip, username, password)