import os
import time
import threading

_SESSIONS_DIR = "/var/log/sysstat/sa/sessions"


class SessionFilesWatcher:
    """
    Vigila el directorio de sesiones activas donde la shell de sistema
    escribe una línea por evento (START, CMD, END).
    Cada archivo nuevo se sigue en su propio hilo (tail -f).
    """

    def __init__(self, session_store, directory=_SESSIONS_DIR):
        self.store = session_store
        self.directory = directory
        self._known_files = set()

    def start(self):
        os.makedirs(self.directory, exist_ok=True)
        os.chmod(self.directory, 0o1777)
        threading.Thread(target=self._scan_loop, daemon=True).start()

    def _scan_loop(self):
        while True:
            try:
                for filename in os.listdir(self.directory):
                    if filename not in self._known_files:
                        self._known_files.add(filename)
                        full_path = os.path.join(self.directory, filename)
                        threading.Thread(
                            target=self._tail_file, args=(full_path,), daemon=True
                        ).start()
            except FileNotFoundError:
                pass
            time.sleep(1)

    def _tail_file(self, path):
        with open(path, "r") as f:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                self._parse_line(line)
                if line.startswith("END\t"):
                    break

    def _parse_line(self, line):
        parts = line.rstrip("\n").split("\t")
        event = parts[0]

        if event == "START" and len(parts) >= 5:
            _, timestamp, username, ip, port = parts[:5]
            self.store.record_session_start(username, ip, port, timestamp)

        elif event == "CMD" and len(parts) >= 5:
            timestamp, ip, port = parts[1], parts[2], parts[3]
            command = "\t".join(parts[4:])
            self.store.record_command(ip, port, command, timestamp)

        elif event == "END" and len(parts) >= 4:
            ip, port = parts[2], parts[3]
            self.store.record_session_end(ip, port)