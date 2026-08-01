import re
import subprocess
import threading

FAILED_INVALID_RE = re.compile(
    r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
FAILED_RE = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
DISCONNECT_RE = re.compile(
    r"(?:Received disconnect from|Connection closed by|Disconnected from)"
    r"(?: (?:invalid user|user) \S+)? (?P<ip>\S+) port (?P<port>\d+)"
)
CONNECTION_RE = re.compile(
    r"Connection from (?P<ip>\S+) port (?P<port>\d+)"
)


class AuthStream:
    """
    Lanza sshd como subproceso propio para leer su stderr línea por línea.

    Responsabilidades de este módulo (post-refactor):
      - Detectar nuevas conexiones y registrarlas en el store.
      - Detectar login aceptado y marcarlo en el store.
      - Detectar desconexión y cerrar la sesión si no fue aceptada.

    Las credenciales (usuario + contraseña) las gestiona exclusivamente
    auth_events.py a partir de lo que captura PAM, eliminando la necesidad
    de coordinar dos fuentes con lógica de pending_passwords.
    """

    def __init__(self, session_store):
        self.store = session_store
        self.process = None

    def start(self):
        self.process = subprocess.Popen(
            ["/usr/sbin/sshd", "-D", "-e"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._read_loop, daemon=True).start()
        return self.process

    def _read_loop(self):
        for line in self.process.stderr:
            print(f"[sshd] {line.strip()}")
            self._parse_line(line)

    def _parse_line(self, line):
        # Nueva conexión entrante
        m = CONNECTION_RE.search(line)
        if m:
            self.store.record_connection(m["ip"], m["port"])
            return

        # Login aceptado — las credenciales ya las tiene PAM
        m = ACCEPTED_RE.search(line)
        if m:
            self.store.record_accepted_password(m["ip"], m["port"], m["user"])
            return

        # Los eventos Failed/Invalid ya no actualizan credenciales;
        # solo sirven para debug en el log de sshd impreso arriba.

        m = DISCONNECT_RE.search(line)
        if m:
            self.store.record_disconnect(m["ip"], m["port"])
            return