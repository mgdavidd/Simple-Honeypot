import threading
from datetime import datetime
import pwd
import os

from common.log_client import send_log

_FINALIZE_GRACE_ACCEPTED  = float(os.getenv("HONEYPOT_GRACE_ACCEPTED",  "1.5"))
_FINALIZE_GRACE_REJECTED  = float(os.getenv("HONEYPOT_GRACE_REJECTED",  "0.5"))


class SessionStore:
    MAX_CREDENTIALS_PER_SESSION = 3

    def __init__(self, service_id: str = None):
        self.service_id = service_id
        if not self.service_id:
            SERVICE_TYPE = os.getenv("SERVICE_TYPE", "ssh")
            REPLICA_ID = os.getenv("REPLICA_ID", "1")
            self.service_id = f"{SERVICE_TYPE}-{REPLICA_ID}"

        self._lock = threading.Lock()
        self._sessions = {}
        # Buffer para credenciales de PAM que llegan antes que sshd registre
        # la conexión (condición de carrera al inicio de cada intento).
        self._pending_passwords = {}

        self.valid_usernames = self._load_valid_usernames()

    def _load_valid_usernames(self):
        valid = set()
        try:
            for entry in pwd.getpwall():
                if entry.pw_shell == '/usr/local/bin/logged-shell':
                    valid.add(entry.pw_name)
        except Exception as e:
            print(f"[SessionStore] Error cargando usuarios válidos: {e}")
            valid = {'admin', 'ubuntu', 'deploy', 'test', 'david', 'juan'}
        return valid

    def _get_or_create(self, ip, port):
        key = (ip, port)
        if key not in self._sessions:
            self._sessions[key] = {
                "ip": ip,
                "port": port,
                "connection_time": datetime.now().isoformat(),
                "username": None,
                "credentials_tried": [],
                "auth_attempts": 0,
                "accepted": False,
                "accepted_username": None,
                "accepted_password": None,
                "last_captured_credential": None,
                "commands": [],
                "sent": False,
                "_finalize_timer": None,
            }
        return self._sessions[key]

    def _build_credential_pair(self, username, password):
        invalid = username not in self.valid_usernames
        if invalid:
            return {"username": username, "invalid_user": True}, invalid
        clean_password = "".join(c for c in password if c.isprintable())
        return {"username": username, "password": clean_password}, invalid

    def _record_credential(self, session, username, password, force=False):
        """Guarda una credencial en la sesión, reemplazando la más antigua si hace falta."""
        pair, _ = self._build_credential_pair(username, password)
        if pair in session["credentials_tried"]:
            return

        if len(session["credentials_tried"]) < self.MAX_CREDENTIALS_PER_SESSION:
            session["credentials_tried"].append(pair)
            return

        if force:
            session["credentials_tried"].pop(0)
            session["credentials_tried"].append(pair)

    def _attach_pending_passwords(self, ip, session):
        """Vuelca el buffer de PAM en la sesión. Llamar dentro de _lock."""
        pending = self._pending_passwords.pop(ip, [])
        for username, password in pending:
            if username and username != "unknown":
                session["username"] = username
            session["auth_attempts"] += 1
            session["last_captured_credential"] = {"username": username, "password": password}
            self._record_credential(session, username, password)
            if username and session.get("accepted_username") == username:
                session["accepted_password"] = password

    def _cancel_timer(self, s):
        """Cancela un timer de finalización pendiente si existe."""
        t = s.get("_finalize_timer")
        if t is not None:
            t.cancel()
            s["_finalize_timer"] = None

    def record_connection(self, ip, port):
        """Nueva conexión TCP detectada por sshd."""
        with self._lock:
            s = self._get_or_create(ip, port)
            self._attach_pending_passwords(ip, s)

    def record_accepted_password(self, ip, port, username):
        """sshd reporta login aceptado."""
        with self._lock:
            s = self._get_or_create(ip, port)
            s["accepted"] = True
            s["accepted_username"] = username
            if not s["username"]:
                s["username"] = username

            captured = s.get("last_captured_credential") or {}
            if username and captured.get("username") == username:
                s["accepted_password"] = captured.get("password", "")
                self._record_credential(s, username, captured.get("password", ""), force=True)

            self._attach_pending_passwords(ip, s)

    def record_disconnect(self, ip, port):
        """sshd reporta desconexión (solo finaliza sesiones no aceptadas)."""
        with self._lock:
            key = (ip, port)
            s = self._sessions.get(key)
            if s is None or s["sent"]:
                return
            if not s["accepted"]:
                self._cancel_timer(s)
                self._schedule_finalize(key, _FINALIZE_GRACE_REJECTED)

    def record_password_capture(self, ip, username, password) -> tuple:
        """
        Registra un intento de credencial capturado por PAM.

        Retorna (found_session, invalid).

        Si sshd aún no registró la conexión, guarda en buffer y se
        adjunta en record_connection / record_accepted_password.
        """
        with self._lock:
            candidates = [
                (key, s) for key, s in self._sessions.items()
                if s["ip"] == ip and not s["sent"]
            ]

            pair, invalid = self._build_credential_pair(username, password)

            if not candidates:
                # sshd aún no abrió la sesión — buffer provisional
                self._pending_passwords.setdefault(ip, []).append(
                    (username, password)
                )
                return (False, invalid)

            _, s = max(candidates, key=lambda item: item[1]["connection_time"])

            if username and username != "unknown":
                s["username"] = username
            s["auth_attempts"] += 1

            s["last_captured_credential"] = {"username": username, "password": password}
            self._record_credential(s, username, password)

            return (True, invalid)

    def record_session_start(self, username, ip, port, timestamp):
        with self._lock:
            s = self._get_or_create(ip, port)
            s["username"] = username
            s["accepted"] = True
            self._attach_pending_passwords(ip, s)

    def record_command(self, ip, port, command, timestamp):
        with self._lock:
            s = self._get_or_create(ip, port)
            s["commands"].append({"command": command, "timestamp": timestamp})

    def record_session_end(self, ip, port):
        """
        El shell de espía terminó. Esperamos el grace period para que
        auth_events.py tenga tiempo de procesar la línea de PAM que
        puede estar todavía en cola (poll cada 0.3 s + overhead de write).
        """
        with self._lock:
            key = (ip, port)
            s = self._sessions.get(key)
            if s is None or s["sent"]:
                return
            self._cancel_timer(s)
            self._schedule_finalize(key, _FINALIZE_GRACE_ACCEPTED)

    def _schedule_finalize(self, key, delay: float):
        """Programa _finalize tras `delay` segundos. Llamar dentro de _lock."""
        s = self._sessions.get(key)
        if s is None:
            return
        t = threading.Timer(delay, self._finalize_deferred, args=(key,))
        t.daemon = True
        t.start()
        s["_finalize_timer"] = t

    def _finalize_deferred(self, key):
        """Llamado por el timer fuera del lock; adquiere el lock y finaliza."""
        with self._lock:
            s = self._sessions.get(key)
            if s is None or s["sent"]:
                return
            self._finalize(key)

    def _finalize(self, key):
        s = self._sessions[key]
        s["sent"] = True

        payload = {
            "ip": s["ip"],
            "port": s["port"],
            "connection_time": s["connection_time"],
            "username": s["username"],
            "accepted_username": s["accepted_username"],
            "accepted_password": s.get("accepted_password"),
            "password": s.get("accepted_password"),
            "auth_attempts": s["auth_attempts"],
            "credentials_tried": s["credentials_tried"],
            "banner": "OpenSSH_8.9p1 Ubuntu",
            "commands": s["commands"],
        }

        send_log(self.service_id, payload)
        del self._sessions[key]