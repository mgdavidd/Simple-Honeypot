"""
Capa de persistencia JSON en volumen Docker.
Guarda el estado que el atacante ve y modifica: posts, usuarios, tablas SQL, etc.
No toca la DB principal de honeypots — eso lo hace log_client.
"""
import os
import json
import threading
from config import DATA_DIR
from common.time_utils import colombia_now

_lock = threading.Lock()


def _path(filename: str) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, filename)


def _read(filename: str, default):
    try:
        with open(_path(filename), "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write(filename: str, data) -> None:
    with _lock:
        with open(_path(filename), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)


# ─── WordPress state ──────────────────────────────────────────────────────────

WP_POSTS_FILE    = "wp_posts.json"
WP_USERS_FILE    = "wp_users.json"
WP_COMMENTS_FILE = "wp_comments.json"
WP_OPTIONS_FILE  = "wp_options.json"

_WP_DEFAULT_POSTS = [
    {
        "id": 1,
        "title": "Hello world!",
        "content": "Welcome to WordPress. This is your first post. Edit or delete it, then start writing!",
        "status": "publish",
        "author": "admin",
        "date": "2024-11-14 10:22:00",
        "categories": ["Uncategorized"],
        "comments": 1,
    },
    {
        "id": 2,
        "title": "Sample Page",
        "content": "This is an example page. It's different from a blog post because it will stay in one place.",
        "status": "publish",
        "author": "admin",
        "date": "2024-11-14 10:22:01",
        "categories": ["Uncategorized"],
        "comments": 0,
    },
    {
        "id": 3,
        "title": "Privacy Policy",
        "content": "Your privacy is critically important to us. This Privacy Policy document describes the types of personal information that is collected and recorded.",
        "status": "draft",
        "author": "admin",
        "date": "2024-11-14 10:22:02",
        "categories": ["Uncategorized"],
        "comments": 0,
    },
]

_WP_DEFAULT_USERS = [
    {
        "id": 1,
        "username": "admin",
        "name": "Administrator",
        "email": "admin@example.com",
        "role": "Administrator",
        "registered": "2024-11-14",
        "posts": 3,
    },
    {
        "id": 2,
        "username": "editor",
        "name": "Jane Editor",
        "email": "editor@example.com",
        "role": "Editor",
        "registered": "2024-11-20",
        "posts": 0,
    },
]

_WP_DEFAULT_OPTIONS = {
    "blogname": "My WordPress Site",
    "blogdescription": "Just another WordPress site",
    "admin_email": "admin@example.com",
    "siteurl": "http://localhost",
    "blogurl": "http://localhost",
    "wp_user_roles": "a:5:{...}",
    "active_plugins": "akismet/akismet.php\nhello-dolly/hello.php",
    "template": "twentytwentyfour",
    "posts_per_page": "10",
    "date_format": "F j, Y",
    "time_format": "g:i a",
    "timezone_string": "America/Bogota",
}


def wp_get_posts():
    return _read(WP_POSTS_FILE, list(_WP_DEFAULT_POSTS))

def wp_get_post(post_id: int):
    return next((p for p in wp_get_posts() if p["id"] == post_id), None)

def wp_save_post(data: dict) -> dict:
    posts = wp_get_posts()
    post_id = data.get("id")
    if post_id:
        posts = [data if p["id"] == post_id else p for p in posts]
    else:
        data["id"] = max((p["id"] for p in posts), default=0) + 1
        data.setdefault("date", colombia_now().strftime("%Y-%m-%d %H:%M:%S"))
        data.setdefault("comments", 0)
        posts.append(data)
    _write(WP_POSTS_FILE, posts)
    return data

def wp_delete_post(post_id: int) -> bool:
    posts = wp_get_posts()
    new = [p for p in posts if p["id"] != post_id]
    if len(new) == len(posts):
        return False
    _write(WP_POSTS_FILE, new)
    return True

def wp_get_users():
    return _read(WP_USERS_FILE, list(_WP_DEFAULT_USERS))

def wp_save_user(data: dict) -> dict:
    users = wp_get_users()
    uid = data.get("id")
    if uid:
        users = [data if u["id"] == uid else u for u in users]
    else:
        data["id"] = max((u["id"] for u in users), default=0) + 1
        data.setdefault("registered", colombia_now().strftime("%Y-%m-%d"))
        data.setdefault("posts", 0)
        users.append(data)
    _write(WP_USERS_FILE, users)
    return data

def wp_delete_user(user_id: int) -> bool:
    users = wp_get_users()
    new = [u for u in users if u["id"] != user_id]
    if len(new) == len(users):
        return False
    _write(WP_USERS_FILE, new)
    return True

def wp_get_options():
    return _read(WP_OPTIONS_FILE, dict(_WP_DEFAULT_OPTIONS))

def wp_save_options(updates: dict) -> dict:
    opts = wp_get_options()
    opts.update(updates)
    _write(WP_OPTIONS_FILE, opts)
    return opts


# ─── phpMyAdmin / MySQL state ─────────────────────────────────────────────────

PMA_DB_FILE = "pma_databases.json"

_PMA_DEFAULT_DB = {
    "information_schema": {
        "tables": {
            "TABLES": {
                "columns": ["TABLE_CATALOG","TABLE_SCHEMA","TABLE_NAME","TABLE_TYPE","ENGINE","TABLE_ROWS"],
                "rows": [
                    ["def","information_schema","TABLES","BASE TABLE","InnoDB",25],
                    ["def","information_schema","COLUMNS","BASE TABLE","InnoDB",1000],
                ],
                "engine": "InnoDB", "collation": "utf8_general_ci", "size": "16 KiB",
            },
        }
    },
    "mysql": {
        "tables": {
            "user": {
                "columns": ["Host","User","authentication_string","plugin","password_expired"],
                "rows": [
                    ["localhost","root","*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19","caching_sha2_password","N"],
                    ["localhost","mysql.sys","","caching_sha2_password","N"],
                    ["%","honeypot","*A4B6157319038724E3560894F7F932C8886EBFCF","caching_sha2_password","N"],
                ],
                "engine": "MyISAM", "collation": "utf8mb3_bin", "size": "6 KiB",
            },
            "db": {
                "columns": ["Host","Db","User","Select_priv","Insert_priv","Update_priv"],
                "rows": [
                    ["%","honeypot","honeypot","Y","Y","Y"],
                ],
                "engine": "MyISAM", "collation": "utf8mb3_bin", "size": "4 KiB",
            },
        }
    },
    "wordpress": {
        "tables": {
            "wp_users": {
                "columns": ["ID","user_login","user_pass","user_email","user_registered","user_status"],
                "rows": [
                    [1,"admin","$P$BIRXVj/ZG0YRiBH8gnRSJMkx4BNJ0/1","admin@example.com","2024-11-14 10:22:00",0],
                    [2,"editor","$P$BDHbEiG.Yf3B5DQv5IlHH4eEhOxqM1.","editor@example.com","2024-11-20 08:15:00",0],
                ],
                "engine": "InnoDB", "collation": "utf8mb4_unicode_ci", "size": "48 KiB",
            },
            "wp_posts": {
                "columns": ["ID","post_author","post_date","post_title","post_status","post_type"],
                "rows": [
                    [1,1,"2024-11-14 10:22:00","Hello world!","publish","post"],
                    [2,1,"2024-11-14 10:22:01","Sample Page","publish","page"],
                    [3,1,"2024-11-14 10:22:02","Privacy Policy","draft","page"],
                ],
                "engine": "InnoDB", "collation": "utf8mb4_unicode_ci", "size": "96 KiB",
            },
            "wp_options": {
                "columns": ["option_id","option_name","option_value","autoload"],
                "rows": [
                    [1,"siteurl","http://localhost","yes"],
                    [2,"blogname","My WordPress Site","yes"],
                    [36,"admin_email","admin@example.com","yes"],
                    [37,"blogdescription","Just another WordPress site","yes"],
                ],
                "engine": "InnoDB", "collation": "utf8mb4_unicode_ci", "size": "1.2 MiB",
            },
            "wp_usermeta": {
                "columns": ["umeta_id","user_id","meta_key","meta_value"],
                "rows": [
                    [1,1,"wp_capabilities",'a:1:{s:13:"administrator";b:1;}'],
                    [2,1,"wp_user_level","10"],
                ],
                "engine": "InnoDB", "collation": "utf8mb4_unicode_ci", "size": "64 KiB",
            },
            "wp_comments": {
                "columns": ["comment_ID","comment_post_ID","comment_author","comment_content","comment_date"],
                "rows": [
                    [1,1,"A WordPress Commenter","Hi, this is a comment.","2024-11-14 10:22:00"],
                ],
                "engine": "InnoDB", "collation": "utf8mb4_unicode_ci", "size": "32 KiB",
            },
        }
    },
    "performance_schema": {
        "tables": {
            "events_statements_summary_by_digest": {
                "columns": ["SCHEMA_NAME","DIGEST","DIGEST_TEXT","COUNT_STAR","SUM_TIMER_WAIT"],
                "rows": [],
                "engine": "PERFORMANCE_SCHEMA", "collation": "utf8mb4_0900_ai_ci", "size": "0 B",
            },
        }
    },
}


def pma_get_databases():
    return _read(PMA_DB_FILE, dict(_PMA_DEFAULT_DB))

def pma_get_db(db_name: str):
    return pma_get_databases().get(db_name)

def pma_get_table(db_name: str, table_name: str):
    db = pma_get_db(db_name)
    if not db:
        return None
    return db.get("tables", {}).get(table_name)

def pma_insert_row(db_name: str, table_name: str, values: list) -> bool:
    dbs = pma_get_databases()
    try:
        dbs[db_name]["tables"][table_name]["rows"].append(values)
        _write(PMA_DB_FILE, dbs)
        return True
    except KeyError:
        return False

def pma_delete_row(db_name: str, table_name: str, row_index: int) -> bool:
    dbs = pma_get_databases()
    try:
        rows = dbs[db_name]["tables"][table_name]["rows"]
        if 0 <= row_index < len(rows):
            rows.pop(row_index)
            _write(PMA_DB_FILE, dbs)
            return True
    except KeyError:
        pass
    return False

def pma_execute_sql(db_name: str, sql: str) -> dict:
    """
    Simula ejecución SQL. Devuelve un resultado fake pero plausible.
    Para SELECT devuelve filas de la tabla mencionada si existe.
    Para INSERT/UPDATE/DELETE simula rows affected.
    No modifica el estado real — sólo retorna respuesta visual.
    """
    sql_upper = sql.strip().upper()
    result = {"sql": sql, "db": db_name, "error": None, "rows": [], "columns": [], "affected": 0, "type": "other"}

    if sql_upper.startswith("SELECT"):
        result["type"] = "select"
        # Intentar extraer tabla del FROM
        import re
        m = re.search(r"FROM\s+`?(\w+)`?", sql_upper)
        if m:
            tname = m.group(1).lower()
            # buscar en cualquier BD si no está en la actual
            dbs = pma_get_databases()
            table = (dbs.get(db_name, {}).get("tables", {}).get(tname)
                     or next((d["tables"].get(tname) for d in dbs.values() if tname in d.get("tables", {})), None))
            if table:
                result["columns"] = table["columns"]
                result["rows"] = table["rows"][:100]
            else:
                result["columns"] = ["(no columns)"]
                result["rows"] = []
        result["affected"] = len(result["rows"])

    elif sql_upper.startswith(("INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE")):
        result["type"] = sql_upper.split()[0].lower()
        result["affected"] = 1
        # Para DROP TABLE, podemos eliminarla del state
        if sql_upper.startswith("DROP TABLE"):
            import re
            m = re.search(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?(\w+)`?", sql_upper)
            if m:
                tname = m.group(1).lower()
                dbs = pma_get_databases()
                if db_name in dbs and tname in dbs[db_name].get("tables", {}):
                    del dbs[db_name]["tables"][tname]
                    _write(PMA_DB_FILE, dbs)
                    result["affected"] = 1

    elif sql_upper.startswith("SHOW"):
        result["type"] = "show"
        if "TABLES" in sql_upper:
            db = pma_get_db(db_name)
            result["columns"] = [f"Tables_in_{db_name}"]
            result["rows"] = [[t] for t in (db.get("tables", {}).keys() if db else [])]
        elif "DATABASES" in sql_upper:
            result["columns"] = ["Database"]
            result["rows"] = [[d] for d in pma_get_databases().keys()]
        result["affected"] = len(result["rows"])

    elif sql_upper.startswith("DESCRIBE") or sql_upper.startswith("DESC"):
        result["type"] = "describe"
        import re
        m = re.search(r"(?:DESCRIBE|DESC)\s+`?(\w+)`?", sql_upper)
        if m:
            tname = m.group(1).lower()
            table = pma_get_table(db_name, tname)
            if table:
                result["columns"] = ["Field","Type","Null","Key","Default","Extra"]
                result["rows"] = [[c, "varchar(255)", "YES", "", "NULL", ""] for c in table["columns"]]
        result["affected"] = len(result["rows"])

    return result