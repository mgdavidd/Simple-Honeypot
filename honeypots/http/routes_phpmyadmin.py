"""
Blueprint phpMyAdmin honeypot.
Rutas: /phpmyadmin/, /phpmyadmin/index.php, /phpmyadmin/sql.php,
       /phpmyadmin/tbl_structure.php, /phpmyadmin/tbl_browse.php, etc.
Estado persistente en JSON via store.py
"""
import json as _json
import secrets
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, make_response, session
from common.log_client import send_log
from config import SERVICE_ID, brute_force_guard
from credentials import validate_credentials
import store

pma = Blueprint("pma", __name__)

PMA_PREFIX = "/phpmyadmin"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip():
    return request.remote_addr

def _ua():
    return request.headers.get("User-Agent", "")

def _log_page(path, status=200):
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "page_view",
        "method": request.method,
        "path": path,
        "user_agent": _ua(),
        "status_code": status,
        "response_size": 0,
    })

def _log_login(username, password, success):
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "login_attempt",
        "method": "POST",
        "path": f"{PMA_PREFIX}/index.php",
        "user_agent": _ua(),
        "username": username,
        "password": password,
        "login_success": success,
        "status_code": 302 if success else 200,
        "response_size": 0,
    })

def _log_sql(db, sql, result):
    body = {
        "db": db,
        "sql": sql[:500],
        "sql_type": result.get("type", "other"),
        "rows_returned": len(result.get("rows", [])),
        "rows_affected": result.get("affected", 0),
        "columns": result.get("columns", []),
        # Preview de las primeras 3 filas para dar contexto sin saturar el log
        "rows_preview": result.get("rows", [])[:3],
        "error": result.get("error"),
    }
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "other_form",
        "method": "POST",
        "path": f"{PMA_PREFIX}/sql.php",
        "user_agent": _ua(),
        "form_data": body,
        "action_label": f"pma_sql_{result.get('type', 'query')}",
        "body": body,
        "status_code": 200,
        "response_size": 0,
    })

def _is_authenticated():
    return session.get("pma_logged_in") is True

def _require_auth():
    if not _is_authenticated():
        return redirect(f"{PMA_PREFIX}/index.php")
    return None

def _current_db():
    return request.args.get("db") or session.get("pma_db", "")

def _current_table():
    return request.args.get("table") or request.args.get("tbl", "")


# ── Login / Logout ────────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/", methods=["GET"])
@pma.route(f"{PMA_PREFIX}/index.php", methods=["GET", "POST"])
def pma_login():
    if request.method == "GET":
        _log_page(request.path)
        if _is_authenticated():
            return redirect(f"{PMA_PREFIX}/sql.php")
        token = secrets.token_hex(16)
        session["pma_token"] = token
        return render_template("pma_login.html", error=None, token=token)

    # POST login
    form     = dict(request.form)
    username = form.get("pma_username") or form.get("username", "")
    password = form.get("pma_password") or form.get("password", "")
    valid    = validate_credentials(username, password)
    _log_login(username, password, valid)

    if valid:
        session["pma_logged_in"] = True
        session["pma_username"]  = username
        session["pma_db"]        = "wordpress"
        resp = make_response(redirect(f"{PMA_PREFIX}/sql.php?db=wordpress"))
        resp.set_cookie("phpMyAdmin", secrets.token_hex(16),
                        httponly=True, samesite="Lax", max_age=3600)
        return resp

    brute_force_guard.record_attempt(ip=_ip(), username=username, password=password)
    token = secrets.token_hex(16)
    session["pma_token"] = token
    return render_template("pma_login.html",
                           error="Access denied for user '{}'@'{}' (using password: YES)".format(
                               username, _ip()),
                           token=token), 200


@pma.route(f"{PMA_PREFIX}/logout.php", methods=["GET"])
def pma_logout():
    _log_page(f"{PMA_PREFIX}/logout.php")
    session.clear()
    resp = make_response(redirect(f"{PMA_PREFIX}/index.php?old_usr="))
    resp.delete_cookie("phpMyAdmin")
    return resp


# ── Main frame / server overview ─────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/sql.php", methods=["GET", "POST"])
def pma_sql():
    redir = _require_auth()
    if redir: return redir

    db    = request.args.get("db") or request.form.get("db") or session.get("pma_db", "")
    table = request.args.get("table") or request.form.get("table") or ""
    if db:
        session["pma_db"] = db

    dbs      = store.pma_get_databases()
    username = session.get("pma_username", "root")

    if request.method == "POST":
        sql    = request.form.get("sql_query", "").strip()
        result = store.pma_execute_sql(db, sql)
        _log_sql(db, sql, result)
        _log_page(f"{PMA_PREFIX}/sql.php", 200)
        return render_template("pma_sql.html",
                               username=username,
                               databases=list(dbs.keys()),
                               current_db=db,
                               current_table=table,
                               result=result,
                               sql=sql)

    _log_page(f"{PMA_PREFIX}/sql.php")
    return render_template("pma_sql.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=db,
                           current_table=table,
                           result=None,
                           sql="")


# ── Table browser ─────────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/tbl_select.php", methods=["GET"])
@pma.route(f"{PMA_PREFIX}/tbl_browse.php", methods=["GET"])
def pma_tbl_browse():
    redir = _require_auth()
    if redir: return redir

    db    = _current_db()
    table = _current_table()
    if db:
        session["pma_db"] = db

    # Sin tabla seleccionada redirigir a la estructura de la BD
    if not table:
        return redirect(f"{PMA_PREFIX}/db_structure.php?db={db}" if db
                        else f"{PMA_PREFIX}/sql.php")

    _log_page(request.path)

    dbs      = store.pma_get_databases()
    tbl_data = store.pma_get_table(db, table)
    username = session.get("pma_username", "root")

    return render_template("pma_browse.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=db,
                           current_table=table,
                           db_tables=list(dbs.get(db, {}).get("tables", {}).keys()),
                           table_data=tbl_data)


# ── Table structure ───────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/tbl_structure.php", methods=["GET"])
def pma_tbl_structure():
    redir = _require_auth()
    if redir: return redir

    db    = _current_db()
    table = _current_table()
    if db:
        session["pma_db"] = db

    if not table:
        return redirect(f"{PMA_PREFIX}/db_structure.php?db={db}" if db
                        else f"{PMA_PREFIX}/sql.php")

    _log_page(request.path)

    dbs      = store.pma_get_databases()
    tbl_data = store.pma_get_table(db, table)
    username = session.get("pma_username", "root")

    return render_template("pma_structure.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=db,
                           current_table=table,
                           db_tables=list(dbs.get(db, {}).get("tables", {}).keys()),
                           table_data=tbl_data)


# ── Insert row ────────────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/tbl_change.php", methods=["GET", "POST"])
def pma_tbl_change():
    redir = _require_auth()
    if redir: return redir

    db    = _current_db() or request.form.get("db", "")
    table = _current_table() or request.form.get("table", "")
    if db:
        session["pma_db"] = db

    if not table and request.method == "GET":
        return redirect(f"{PMA_PREFIX}/db_structure.php?db={db}" if db
                        else f"{PMA_PREFIX}/sql.php")

    dbs      = store.pma_get_databases()
    tbl_data = store.pma_get_table(db, table)
    username = session.get("pma_username", "root")

    if request.method == "POST":
        form   = dict(request.form)
        values = [form.get(f"fields_value[{c}]", "") for c in (tbl_data["columns"] if tbl_data else [])]
        store.pma_insert_row(db, table, values)
        body = {
            "db": db,
            "table": f"{db}.{table}",
            "columns": (tbl_data["columns"] if tbl_data else []),
            "values_inserted": values,
            # Zip para ver columna→valor de forma legible
            "row": dict(zip(tbl_data["columns"], values)) if tbl_data else {},
        }
        send_log(SERVICE_ID, {
            "ip": _ip(),
            "request_type": "other_form",
            "method": "POST",
            "path": f"{PMA_PREFIX}/tbl_change.php",
            "user_agent": _ua(),
            "form_data": body,
            "action_label": "pma_insert_row",
            "body": body,
            "status_code": 302,
            "response_size": 0,
        })
        _log_page(request.path)
        return redirect(f"{PMA_PREFIX}/tbl_browse.php?db={db}&table={table}&pos=0")

    _log_page(request.path)
    return render_template("pma_change.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=db,
                           current_table=table,
                           db_tables=list(dbs.get(db, {}).get("tables", {}).keys()),
                           table_data=tbl_data)


# ── Delete row ────────────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/tbl_delete_row.php", methods=["POST"])
def pma_delete_row():
    redir = _require_auth()
    if redir: return redir

    db        = request.form.get("db", "")
    table     = request.form.get("table", "")
    row_index = int(request.form.get("row_index", -1))

    if row_index >= 0:
        # Capturar la fila ANTES de borrarla para el log
        tbl = store.pma_get_table(db, table)
        deleted_row = None
        if tbl and 0 <= row_index < len(tbl.get("rows", [])):
            deleted_row = dict(zip(tbl["columns"], tbl["rows"][row_index]))
        store.pma_delete_row(db, table, row_index)
        body = {
            "db": db,
            "table": f"{db}.{table}",
            "row_index": row_index,
            "deleted_row": deleted_row,
        }
        send_log(SERVICE_ID, {
            "ip": _ip(),
            "request_type": "other_form",
            "method": "POST",
            "path": f"{PMA_PREFIX}/tbl_delete_row.php",
            "user_agent": _ua(),
            "form_data": body,
            "action_label": "pma_delete_row",
            "body": body,
            "status_code": 302,
            "response_size": 0,
        })

    return redirect(f"{PMA_PREFIX}/tbl_browse.php?db={db}&table={table}&pos=0")


# ── Database overview ─────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/db_structure.php", methods=["GET"])
def pma_db_structure():
    redir = _require_auth()
    if redir: return redir

    db = _current_db()
    if db:
        session["pma_db"] = db

    _log_page(request.path)
    dbs      = store.pma_get_databases()
    db_data  = dbs.get(db, {})
    username = session.get("pma_username", "root")

    # Calcular tamaño total
    tables_info = []
    for tname, tdata in db_data.get("tables", {}).items():
        tables_info.append({
            "name": tname,
            "rows": len(tdata.get("rows", [])),
            "engine": tdata.get("engine", "InnoDB"),
            "collation": tdata.get("collation", "utf8mb4_unicode_ci"),
            "size": tdata.get("size", "16 KiB"),
        })

    return render_template("pma_db_structure.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=db,
                           current_table="",
                           db_tables=list(db_data.get("tables", {}).keys()),
                           tables_info=tables_info)


# ── Server status (stub) ──────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/server_status.php", methods=["GET"])
def pma_server_status():
    redir = _require_auth()
    if redir: return redir
    _log_page(request.path)
    dbs      = store.pma_get_databases()
    username = session.get("pma_username", "root")
    current_db = session.get("pma_db", "")
    db_tables  = list(dbs.get(current_db, {}).get("tables", {}).keys())
    return render_template("pma_server_status.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=current_db,
                           current_table="",
                           db_tables=db_tables)


# ── User privileges ───────────────────────────────────────────────────────────

@pma.route(f"{PMA_PREFIX}/server_privileges.php", methods=["GET"])
def pma_privileges():
    redir = _require_auth()
    if redir: return redir
    _log_page(request.path)
    dbs      = store.pma_get_databases()
    username = session.get("pma_username", "root")
    users_table = store.pma_get_table("mysql", "user")
    current_db = session.get("pma_db", "")
    db_tables  = list(dbs.get(current_db, {}).get("tables", {}).keys())
    return render_template("pma_privileges.html",
                           username=username,
                           databases=list(dbs.keys()),
                           current_db=current_db,
                           current_table="",
                           db_tables=db_tables,
                           users=users_table)