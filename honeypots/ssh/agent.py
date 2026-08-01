import os

from monitor.session_store import SessionStore
from monitor.auth_stream import AuthStream
from monitor.auth_events import AuthEventsWatcher
from monitor.session_files import SessionFilesWatcher
from common.brute_force_guard import BruteForceGuard
from common.ip_blocker import IPBlocker


def main():
    SERVICE_TYPE = os.getenv("SERVICE_TYPE")
    REPLICA_ID = os.getenv("REPLICA_ID")
    SERVICE_ID = f"{SERVICE_TYPE}-{REPLICA_ID}"

    store = SessionStore(service_id=SERVICE_ID)
    guard = BruteForceGuard(service_id=SERVICE_ID, blocker=IPBlocker())

    def on_password_captured(ip, username, password):
        """
        Callback invocado por AuthEventsWatcher cada vez que PAM registra
        un intento. Es la única ruta por la que se añaden credenciales.
        """
        _found, invalid = store.record_password_capture(ip, username, password)
        guard.record_attempt(ip, username, password, invalid=invalid)

    sshd_process = AuthStream(store).start()
    print("[agent] sshd lanzado, escuchando eventos de autenticación...")

    AuthEventsWatcher(on_password_captured).start()
    print("[agent] Vigilando contraseñas capturadas por PAM...")

    SessionFilesWatcher(store).start()
    print("[agent] Vigilando comandos ejecutados en sesiones...")

    sshd_process.wait()
    print("[agent] sshd terminó, cerrando agente.")


if __name__ == "__main__":
    main()