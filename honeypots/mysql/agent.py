import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, '/app')

try:
    from honeypots.common.log_client import send_log, send_bruteforce_alert
    from honeypots.common.ip_blocker import IPBlocker
except ImportError:
    try:
        from common.log_client import send_log, send_bruteforce_alert
        from common.ip_blocker import IPBlocker
    except ImportError:
        print("[mysql-agent] ERROR: No puede importar módulos comunes")
        sys.exit(1)

SERVICE_TYPE     = os.getenv("SERVICE_TYPE", "mysql")
REPLICA_ID       = os.getenv("REPLICA_ID", "1")
SERVICE_ID       = f"{SERVICE_TYPE}-{REPLICA_ID}"
TEMPLATE_NAME    = os.getenv("TEMPLATE_NAME", "empty")
LOG_FILE         = "/var/log/mysql/general.log"
FAILED_THRESHOLD = int(os.getenv("CONFIG_FAILED_THRESHOLD", "20"))
BAN_SECONDS      = int(os.getenv("CONFIG_BAN_SECONDS", "600"))
# "verbose"  → log everything (current behaviour)
# "filtered" → drop monitoring noise, only keep queries with attacker intent
LOG_MODE         = os.getenv("CONFIG_LOG_MODE", "verbose").lower()

print(f"[mysql-agent] {SERVICE_ID} iniciado | Template: {TEMPLATE_NAME} | Log mode: {LOG_MODE}")


# ── Análisis de queries ───────────────────────────────────────────────────────

class QueryAnalyzer:
    SQLI_PATTERNS = {
        "union_based":    r"UNION\s+(ALL\s+)?SELECT",
        "time_based":     r"SLEEP\s*\(|BENCHMARK\s*\(",
        "boolean_based":  r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        "error_based":    r"EXTRACTVALUE|UPDATEXML|JSON_EXTRACT",
        "stacked_queries":r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE)",
        "comment_inject": r"--\s+|#\s*$|/\*.*?\*/",
    }
    TOOL_SIGNATURES = {
        "sqlmap": [r"UNION.*SELECT.*NULL", r"AND\s+\d+\s*LIKE\s*CHAR", r"version\(\)|database\(\)|user\(\)"],
        "havij":  [r"UNION.*ALL.*SELECT", r"/\*!\d+.*?\*/"],
        "burp":   [r"UNION.*SELECT.*1\s*,\s*2\s*,\s*3", r"' OR '1'='1"],
    }

    @classmethod
    def sqli_pattern(cls, query: str) -> str:
        for name, pat in cls.SQLI_PATTERNS.items():
            if re.search(pat, query, re.IGNORECASE):
                return name
        return "none"

    @classmethod
    def detect_tool(cls, query: str) -> str:
        for tool, sigs in cls.TOOL_SIGNATURES.items():
            if sum(1 for s in sigs if re.search(s, query, re.IGNORECASE)) >= 2:
                return tool
        return "manual"

    @classmethod
    def query_type(cls, query: str) -> str:
        first = query.strip().split()[0].upper() if query.strip() else ""
        return {
            "SELECT": "select", "INSERT": "insert", "UPDATE": "update",
            "DELETE": "delete", "DROP":   "drop",   "CREATE": "create",
            "ALTER":  "alter",  "USE":    "use",    "SHOW":   "show",
            "DESCRIBE": "describe",
        }.get(first, "other")


# ── Filtro de ruido (modo filtered) ──────────────────────────────────────────

class NoiseFilter:
    """
    Decide si una query debe descartarse cuando LOG_MODE == 'filtered'.

    Ruido típico de clientes legítimos / monitoring:
      - Health checks de MySQL Workbench, Prometheus exporters, etc.
      - Comandos administrativos automáticos de drivers y ORMs.
      - Queries de introspección que no revelan intención ofensiva.

    Se conserva SIEMPRE:
      - Cualquier query con un patrón SQLi detectado.
      - DML sobre tablas de usuario (INSERT / UPDATE / DELETE / DROP / ALTER / CREATE).
      - SELECT con cláusulas que sugieren enumeración (UNION, INFORMATION_SCHEMA, etc.).
      - Comandos que establecen contexto interesante (USE <db>, LOAD DATA, CALL, EXEC).
    """

    # Queries exactas (case-insensitive) que son puro ruido de monitoring
    _EXACT_NOISE: set[str] = {
        "show global status",
        "show status",
        "show variables",
        "show global variables",
        "show slave status",
        "show replica status",
        "show processlist",
        "show full processlist",
        "show engine innodb status",
        "select 1",
        "select 1 as keepalive",
        "select now()",
        "select version()",
        "select database()",
        "select user()",
        "select current_user()",
    }

    # Prefijos de ruido (case-insensitive).  Solo se aplican si la query NO tiene SQLi.
    _NOISE_PREFIXES: tuple[str, ...] = (
        # Workbench / drivers — introspección de esquema
        "select @@",
        "set names",
        "set character_set",
        "set autocommit",
        "set session",
        "set global",
        "set @@",
        "set sql_mode",
        "set time_zone",
        "set foreign_key_checks",
        "set unique_checks",
        "set sql_safe_updates",
        "set net_write_timeout",
        "set net_read_timeout",
        "set wait_timeout",
        "show create table",
        "show create database",
        "show tables",
        "show columns",
        "show full columns",
        "show index",
        "show keys",
        "show triggers",
        "show events",
        "show warnings",
        "show errors",
        "show grants",
        "show charset",
        "show collation",
        "show engines",
        "show plugins",
        "show open tables",
        "show binary logs",
        "show master status",
        "show databases",
        # ORM / driver ping patterns
        "/* ping */",
        "/* mysql-connector",
        "/* jdbc",
        # MySQL Workbench metadata queries
        "select table_name",
        "select column_name",
        "select schema_name",
        "select routine_name",
        "select trigger_name",
        "select constraint_name",
        "select view_name",
        "information_schema.tables",
        "information_schema.columns",
        "information_schema.routines",
        "information_schema.triggers",
        "information_schema.views",
        "information_schema.statistics",
        "information_schema.key_column_usage",
        "information_schema.referential_constraints",
        "performance_schema.",
        "sys.",
        # Workbench session bootstrap
        "select @@lower_case_table_names",
        "select @@version_comment",
        "select @@session.transaction_read_only",
        "commit",
        "rollback",
        "start transaction",
        "begin",
        "savepoint",
        "release savepoint",
    )

    # Si la query contiene ANY of these tokens it is always interesting
    _ALWAYS_INTERESTING_RE = re.compile(
        r"""
        \b(UNION|INFORMATION_SCHEMA|LOAD\s+DATA|INTO\s+OUTFILE|INTO\s+DUMPFILE|
           SLEEP\s*\(|BENCHMARK\s*\(|EXTRACTVALUE|UPDATEXML|
           EXEC\s*\(|EXECUTE|XP_CMDSHELL|OPENROWSET|
           DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE|
           ALTER\s+TABLE|CREATE\s+USER|GRANT\s+ALL|
           CALL\s+\w|PROCEDURE|FUNCTION)\b
        |--\s|#\s*$|/\*.*?\*/
        """,
        re.IGNORECASE | re.VERBOSE | re.DOTALL,
    )

    @classmethod
    def should_drop(cls, query: str, sqli_pattern: str) -> bool:
        """Return True when the query is noise and should NOT be logged."""
        # Never drop queries that already triggered a SQLi pattern
        if sqli_pattern != "none":
            return False

        # Never drop if the query contains clearly interesting tokens
        if cls._ALWAYS_INTERESTING_RE.search(query):
            return False

        q = query.strip().lower()

        if q in cls._EXACT_NOISE:
            return True

        for prefix in cls._NOISE_PREFIXES:
            if q.startswith(prefix) or prefix in q:
                return True

        return False


# ── Monitor principal ─────────────────────────────────────────────────────────

class MySQLAgentMonitor:
    """
    Filosofía de logging:
    - Registra CONSULTAS de sesiones autenticadas (lo valioso del honeypot MySQL).
    - Detecta BRUTE-FORCE de forma silenciosa: cuenta intentos fallidos y bloquea
      la IP al llegar al umbral, registrando solo la alerta final en brute_force_alerts.
    - NO registra cada intento fallido individual en mysql_queries (ensuciaría los logs).

    Detección de login fallido en MySQL 8:
    - El general log emite "Connect" para AMBOS casos (éxito y contraseña incorrecta).
    - Los fallos se detectan por "Connect_Error" (usuario inexistente) o midiendo
      el tiempo entre Connect y el primer evento posterior:
      si no llega Query y el timeout expira → fue rechazado.
    """

    LINE_RE = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+"
        r"(\d+)\s+"
        r"(\w+)\s*"
        r"(.*)"
    )

    # Segundos sin Query tras un Connect para considerarlo fallido
    CONNECT_TIMEOUT = 3.0

    def __init__(self):
        self.file_pos    = 0
        # conn_id -> {ip, username, db, ts, confirmed}
        # confirmed=True  → recibió Query (login exitoso)
        # confirmed=False → Connect reciente, aún sin Query
        self.conn_map    = {}
        self._failed     = defaultdict(list)   # ip -> [{username, password}]
        self._banned_ips = set()
        self._blocker    = IPBlocker()
        self._last_read  = time.monotonic()

    # ── Lectura del log ───────────────────────────────────────────────────────

    def read_new_logs(self):
        try:
            with open(LOG_FILE, "r", errors="replace") as f:
                f.seek(self.file_pos)
                for line in f:
                    self._process_line(line.rstrip("\n"))
                self.file_pos = f.tell()
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[mysql-agent] Error leyendo log: {e}")

        # Resolver conexiones pendientes que han superado el timeout
        self._resolve_pending_connects()

    def _resolve_pending_connects(self):
        """
        Para cada Connect pendiente que lleva más de CONNECT_TIMEOUT segundos
        sin recibir Query → fue un login fallido (contraseña incorrecta).
        """
        now = time.monotonic()
        expired = [
            cid for cid, c in self.conn_map.items()
            if not c["confirmed"] and (now - c["mono_ts"]) >= self.CONNECT_TIMEOUT
        ]
        for conn_id in expired:
            conn = self.conn_map.pop(conn_id)
            ip, username = conn["ip"], conn["username"]
            print(f"[mysql-agent] Login fallido (timeout): {username}@{ip}")

            if ip not in self._banned_ips:
                self._failed[ip].append({"username": username, "password": "unknown"})
                self._check_brute_force(ip, conn["ts"])

    def _process_line(self, line: str):
        m = self.LINE_RE.match(line)
        if not m:
            return
        ts_str, conn_id, event, content = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat()
        except Exception:
            ts = datetime.now().isoformat()

        if event == "Connect":
            self._on_connect(conn_id, content, ts)
        elif event == "Connect_Error":
            self._on_connect_error(conn_id, content, ts)
        elif event == "Query":
            self._on_query(conn_id, content, ts)

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_connect(self, content: str):
        """
        Parsea eventos Connect del general log de MySQL 8.
        Formatos:
          honeypot @ 192.168.1.22  on  using TCP/IP     (sin DB)
          honeypot @ 192.168.1.22  on ecommerce using TCP/IP
          honeypot[honeypot] @ 192.168.1.22 []
          root@192.168.1.22 on honeypot using TCP/IP
        Devuelve (username, ip, db).
        """
        content = re.sub(r'\[.*?\]', '', content).strip()

        db = "unknown"
        on_match = re.search(r'\bon\s+(?!using\b)(\S+)', content, re.IGNORECASE)
        if on_match:
            db = on_match.group(1).rstrip('`\'"')
            content = content[:on_match.start()].strip()
        else:
            content = re.split(r'\s+(?:on|using)\s+', content, maxsplit=1)[0].strip()

        at_match = re.search(r'(\S+)\s*@\s*(\S+)', content)
        if at_match:
            username = at_match.group(1).strip().strip("'\"")
            ip       = at_match.group(2).strip().strip("'\"")
        else:
            username = content.strip()
            ip       = "unknown"

        return username, ip, db

    def _parse_connect_error(self, content: str):
        """
        Connect_Error: Access denied for user 'u'@'ip' (using password: YES)
        """
        m = re.search(r"'([^']+)'@'([^']+)'", content)
        if m:
            return m.group(1), m.group(2)
        username, ip, _ = self._parse_connect(content)
        return username, ip

    def _on_connect(self, conn_id: str, content: str, ts: str):
        username, ip, db = self._parse_connect(content)
        self.conn_map[conn_id] = {
            "ip": ip, "username": username, "db": db,
            "ts": ts, "confirmed": False,
            "mono_ts": time.monotonic(),   # para el timeout de detección de fallo
        }
        
        
    def _on_connect_error(self, conn_id: str, content: str, ts: str):
        """Usuario inexistente — contabilizar para brute-force, sin log en mysql_queries."""
        username, ip = self._parse_connect_error(content)
        self.conn_map.pop(conn_id, None)
        print(f"[mysql-agent] Connect_Error (usuario no existe): {username}@{ip}")

        if ip not in self._banned_ips:
            self._failed[ip].append({"username": username, "password": "unknown"})
            self._check_brute_force(ip, ts)

    def _on_query(self, conn_id: str, content: str, ts: str):
        if conn_id not in self.conn_map:
            return

        conn = self.conn_map[conn_id]

        # Primera Query → confirmar login exitoso, resetear fallos de esta IP
        if not conn["confirmed"]:
            conn["confirmed"] = True
            self._failed.pop(conn["ip"], None)
            print(f"[mysql-agent] Login confirmado: {conn['username']}@{conn['ip']}")

        query = content.strip()
        if not query:
            return

        qtype = QueryAnalyzer.query_type(query)

        # ── Filtro verbose (comportamiento original) ──────────────────────────
        # Descartar solo las queries de bootstrap del driver que no aportan nada
        if LOG_MODE == "verbose":
            if qtype == "other" and (
                query.lower().startswith(("set ", "select 1")) or
                re.match(r"^\s*select\s+@@version_comment\s+limit\s+1\s*$", query, re.IGNORECASE)
            ):
                return

        sqli = QueryAnalyzer.sqli_pattern(query)
        tool = QueryAnalyzer.detect_tool(query) if sqli != "none" else "none"

        # ── Filtro agresivo (modo filtered) ──────────────────────────────────
        # Descarta ruido de monitoring / Workbench / ORMs sin intención ofensiva
        if LOG_MODE == "filtered" and NoiseFilter.should_drop(query, sqli):
            return

        print(f"[mysql-agent] Query ({qtype}) | SQLi={sqli} | mode={LOG_MODE} | {query[:60]}")

        send_log(SERVICE_ID, {
            "ip":            conn["ip"],
            "username":      conn["username"],
            "query":         query[:2000],
            "query_type":    qtype,
            "sqli_pattern":  sqli,
            "detected_tool": tool,
            "template_name": TEMPLATE_NAME,
            "database_name": conn["db"],
            "timestamp":     ts,
        })

    # ── Fuerza bruta ──────────────────────────────────────────────────────────

    def _check_brute_force(self, ip: str, ts: str):
        attempts = self._failed[ip]
        if len(attempts) < FAILED_THRESHOLD:
            return

        self._banned_ips.add(ip)
        creds = list(attempts)
        self._failed.pop(ip, None)

        print(f"[mysql-agent] Brute-force: {ip} ({len(creds)} intentos) → bloqueando {BAN_SECONDS}s")

        send_bruteforce_alert(
            service_id=SERVICE_ID,
            ip=ip,
            total_attempts=len(creds),
            credentials_tried=creds,
            action=f"blocked_{BAN_SECONDS}s",
            detected_at=ts,
        )
        self._blocker.block(ip, seconds=BAN_SECONDS, on_unblock=lambda: self._unban(ip))

    def _unban(self, ip: str):
        self._banned_ips.discard(ip)
        self._failed.pop(ip, None)
        print(f"[mysql-agent] {ip} desbloqueada")


    def _wait_and_enable_log(self):
        import subprocess
        root_pass = os.getenv("MYSQL_ROOT_PASSWORD", "password123")
        db_name   = os.getenv("MYSQL_DATABASE", "honeypot")

        for _ in range(60):
            try:
                r = subprocess.run(
                    ["mysql", "-u", "root", f"-p{root_pass}", "-h", "127.0.0.1",
                     "-e", f"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{db_name}';"],
                    capture_output=True, text=True, timeout=5
                )
                if r.returncode == 0 and db_name in r.stdout:
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            print("[mysql-agent] Timeout esperando init — activando log de todas formas")

        try:
            subprocess.run(
                ["mysql", "-u", "root", f"-p{root_pass}", "-h", "127.0.0.1",
                 "-e", "SET GLOBAL general_log_file='/var/log/mysql/general.log'; SET GLOBAL general_log='ON';"],
                capture_output=True, text=True, timeout=5, check=True
            )
            print("[mysql-agent] General log activado — comenzando monitoreo")
        except Exception as e:
            print(f"[mysql-agent] Error activando general log: {e}")

    # ── Loop ─────────────────────────────────────────────────────────────────

    def run(self):
        print("[mysql-agent] Esperando a que MySQL complete el init...")
        self._wait_and_enable_log()
        print(f"[mysql-agent] Monitoreando {LOG_FILE}")
        while True:
            self.read_new_logs()
            time.sleep(2)


if __name__ == "__main__":
    MySQLAgentMonitor().run()