import subprocess
import threading

CHAIN = "INPUT"


class IPBlocker:
    def __init__(self):
        self._blocked = set()
        self._lock = threading.Lock()

    def block(self, ip, seconds, on_unblock=None):
        with self._lock:
            if ip in self._blocked:
                return
            self._blocked.add(ip)

        # Bloquea TODO el tráfico desde esa IP (sin filtrar por puerto)
        ok = self._run([
            "iptables", "-I", CHAIN, "1", "-p", "tcp", "-s", ip, "-j", "REJECT", "--reject-with", "tcp-reset"
        ])
        if ok:
            print(f"[ip_blocker] {ip} bloqueada por {seconds}s")
        else:
            print(f"[ip_blocker] No se pudo bloquear {ip} (¿faltan capabilities NET_ADMIN?)")

        timer = threading.Timer(seconds, self._unblock, args=(ip, on_unblock))
        timer.daemon = True
        timer.start()

    def _unblock(self, ip, on_unblock):
        self._run([
            "iptables", "-D", CHAIN, "-p", "tcp", "-s", ip, "-j", "REJECT", "--reject-with", "tcp-reset"
        ])
        with self._lock:
            self._blocked.discard(ip)
        print(f"[ip_blocker] {ip} desbloqueada")
        if on_unblock:
            on_unblock()

    def _run(self, cmd) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[ip_blocker] Error ejecutando {' '.join(cmd)}: {e.stderr.strip()}")
            return False
        except FileNotFoundError:
            print("[ip_blocker] iptables no está instalado en el contenedor")
            return False