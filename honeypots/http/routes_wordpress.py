"""
Blueprint WordPress honeypot.
Rutas auténticas: wp-login.php, wp-admin/*, wp-json/*, xmlrpc.php
Estado persistente en JSON via store.py
"""
import secrets
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, make_response, session, url_for
from common.log_client import send_log
from config import SERVICE_ID, brute_force_guard
from credentials import extract_credentials, validate_credentials
import store

wp = Blueprint("wp", __name__)

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

def _log_login(username, password, success, path):
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "login_attempt",
        "method": "POST",
        "path": path,
        "user_agent": _ua(),
        "username": username,
        "password": password,
        "login_success": success,
        "status_code": 302 if success else 200,
        "response_size": 0,
    })

def _log_action(action_label: str, path: str, body: dict = None):
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "other_form",
        "method": request.method,
        "path": path,
        "user_agent": _ua(),
        "form_data": body or {},
        "action_label": action_label,
        "body": body or {},
        "status_code": 200,
        "response_size": 0,
    })

def _is_authenticated():
    return session.get("wp_logged_in") is True

def _require_auth():
    """Redirige al login si no autenticado."""
    if not _is_authenticated():
        return redirect(f"/wp-login.php?redirect_to={request.path}&reauth=1")
    return None

def _login_response(username):
    session["wp_logged_in"] = True
    session["wp_username"] = username
    session["wp_token"] = secrets.token_hex(16)
    resp = make_response(redirect("/wp-admin/"))
    resp.set_cookie("wordpress_logged_in_abc123", secrets.token_hex(32),
                    httponly=True, samesite="Lax", max_age=3600)
    resp.set_cookie("wordpress_sec_abc123", secrets.token_hex(32),
                    httponly=True, samesite="Lax", max_age=3600)
    return resp


# ── wp-login.php ──────────────────────────────────────────────────────────────

@wp.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    if request.method == "GET":
        _log_page("/wp-login.php")
        if _is_authenticated():
            return redirect("/wp-admin/")
        action = request.args.get("action", "login")
        return render_template("wp_login.html",
                               error=None,
                               action=action,
                               redirect_to=request.args.get("redirect_to", "/wp-admin/"))

    # POST
    form = dict(request.form)
    username = form.get("log") or form.get("username") or form.get("user", "")
    password = form.get("pwd") or form.get("password") or form.get("pass", "")
    action   = form.get("wp-submit", "login")

    valid = validate_credentials(username, password)
    _log_login(username, password, valid, "/wp-login.php")

    if valid:
        return _login_response(username)

    brute_force_guard.record_attempt(ip=_ip(), username=username, password=password)
    return render_template("wp_login.html",
                           error="<strong>Error</strong>: The password you entered for the username <strong>{}</strong> is incorrect. <a href=\"/wp-login.php?action=lostpassword\">Lost your password?</a>".format(username),
                           action="login",
                           redirect_to="/wp-admin/"), 200


@wp.route("/wp-login.php", methods=["GET"], endpoint="wp_login_lostpass")
def wp_login_lostpass():
    return redirect("/wp-login.php")


# ── wp-admin/ dashboard ───────────────────────────────────────────────────────

@wp.route("/wp-admin/", methods=["GET"])
@wp.route("/wp-admin/index.php", methods=["GET"])
def wp_dashboard():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/")
    posts   = store.wp_get_posts()
    users   = store.wp_get_users()
    options = store.wp_get_options()
    username = session.get("wp_username", "admin")
    return render_template("wp_dashboard.html",
                           username=username,
                           posts=posts,
                           users=users,
                           options=options,
                           now=datetime.now())


# ── Posts ─────────────────────────────────────────────────────────────────────

@wp.route("/wp-admin/edit.php", methods=["GET"])
def wp_posts_list():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/edit.php")
    posts    = store.wp_get_posts()
    username = session.get("wp_username", "admin")
    post_type = request.args.get("post_type", "post")
    return render_template("wp_posts.html",
                           username=username,
                           posts=posts,
                           post_type=post_type)


@wp.route("/wp-admin/post-new.php", methods=["GET"])
def wp_post_new():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/post-new.php")
    username = session.get("wp_username", "admin")
    return render_template("wp_post_edit.html",
                           username=username,
                           post=None)


@wp.route("/wp-admin/post.php", methods=["GET", "POST"])
def wp_post_edit():
    redir = _require_auth()
    if redir: return redir

    if request.method == "GET":
        post_id = request.args.get("post", type=int)
        action  = request.args.get("action", "edit")
        _log_page(f"/wp-admin/post.php?post={post_id}&action={action}")

        if action == "delete" and post_id:
            store.wp_delete_post(post_id)
            _log_action("wp_delete_post", "/wp-admin/post.php", {
                "post_id": post_id,
            })
            return redirect("/wp-admin/edit.php?deleted=1")

        post     = store.wp_get_post(post_id) if post_id else None
        username = session.get("wp_username", "admin")
        return render_template("wp_post_edit.html",
                               username=username,
                               post=post)

    # POST — guardar post
    # Nota: dict.get() no acepta kwarg type= (eso es request.args.get),
    # por eso usamos request.form.get() directamente con conversión manual.
    raw_post_id = request.form.get("post_ID", "").strip()
    try:
        post_id = int(raw_post_id) if raw_post_id else None
    except (ValueError, TypeError):
        post_id = None

    def _fv(name: str, default: str = "") -> str:
        """Devuelve el valor del form o el default si viene vacío."""
        v = request.form.get(name, "").strip()
        return v if v else default

    now = datetime.now()
    post_data = {
        "id":         post_id,
        "title":      _fv("post_title", "Untitled"),
        "content":    request.form.get("content", ""),
        "status":     _fv("post_status", "draft"),
        "author":     session.get("wp_username", "admin"),
        "date":       (
            _fv("aa", now.strftime("%Y")) + "-" +
            _fv("mm", now.strftime("%m")) + "-" +
            _fv("jj", now.strftime("%d")) + " " +
            _fv("hh", now.strftime("%H")) + ":" +
            _fv("mn", now.strftime("%M")) + ":00"
        ),
        "categories": ["Uncategorized"],
        "comments":   0,
    }
    saved = store.wp_save_post(post_data)
    _log_action("wp_save_post", "/wp-admin/post.php", {
        "post_id": saved["id"],
        "title": post_data["title"],
        "status": post_data["status"],
        "author": post_data["author"],
        "content_length": len(post_data.get("content", "")),
        "content_preview": post_data.get("content", "")[:200],
    })
    return redirect(f"/wp-admin/post.php?post={saved['id']}&action=edit&message=1")


# ── Users ─────────────────────────────────────────────────────────────────────

@wp.route("/wp-admin/users.php", methods=["GET"])
def wp_users():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/users.php")

    action  = request.args.get("action")
    user_id = request.args.get("user", type=int)
    if action == "delete" and user_id:
        store.wp_delete_user(user_id)
        _log_action("wp_delete_user", "/wp-admin/users.php", {"user_id": user_id})
        return redirect("/wp-admin/users.php?deleted=1")

    users    = store.wp_get_users()
    username = session.get("wp_username", "admin")
    return render_template("wp_users.html", username=username, users=users)


@wp.route("/wp-admin/user-new.php", methods=["GET", "POST"])
def wp_user_new():
    redir = _require_auth()
    if redir: return redir

    if request.method == "GET":
        _log_page("/wp-admin/user-new.php")
        return render_template("wp_user_new.html",
                               username=session.get("wp_username", "admin"),
                               message=None, error=None)

    form = dict(request.form)
    new_user = {
        "username": form.get("user_login", ""),
        "name":     form.get("first_name", "") + " " + form.get("last_name", ""),
        "email":    form.get("email", ""),
        "role":     form.get("role", "subscriber").capitalize(),
    }
    saved_user = store.wp_save_user(new_user)
    _log_action("wp_create_user", "/wp-admin/user-new.php", {
        "user_id": saved_user.get("id"),
        "username": new_user.get("username"),
        "email": new_user.get("email"),
        "role": new_user.get("role"),
        "name": new_user.get("name", "").strip(),
    })
    return redirect("/wp-admin/users.php?update=add")


# ── Options / Settings ────────────────────────────────────────────────────────

@wp.route("/wp-admin/options-general.php", methods=["GET", "POST"])
def wp_options():
    redir = _require_auth()
    if redir: return redir

    if request.method == "GET":
        _log_page("/wp-admin/options-general.php")
        options  = store.wp_get_options()
        username = session.get("wp_username", "admin")
        return render_template("wp_options.html", username=username, options=options, saved=False)

    form = dict(request.form)
    updates = {k: v for k, v in form.items()
               if k not in ("_wpnonce", "_wp_http_referer", "action", "submit")}
    store.wp_save_options(updates)
    _log_action("wp_save_options", "/wp-admin/options-general.php", {
        "fields_changed": list(updates.keys()),
        "values": updates,
        "count": len(updates),
    })
    options  = store.wp_get_options()
    username = session.get("wp_username", "admin")
    return render_template("wp_options.html", username=username, options=options, saved=True)


# ── Plugins page (read-only honeypot) ────────────────────────────────────────

@wp.route("/wp-admin/plugins.php", methods=["GET"])
def wp_plugins():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/plugins.php")
    username = session.get("wp_username", "admin")
    return render_template("wp_plugins.html", username=username)


# ── Media (stub) ─────────────────────────────────────────────────────────────

@wp.route("/wp-admin/upload.php", methods=["GET"])
def wp_media():
    redir = _require_auth()
    if redir: return redir
    _log_page("/wp-admin/upload.php")
    username = session.get("wp_username", "admin")
    return render_template("wp_media.html", username=username)


# ── Logout ────────────────────────────────────────────────────────────────────

@wp.route("/wp-login.php/logout", methods=["GET"])
@wp.route("/wp-admin/logout", methods=["GET"])
def wp_logout():
    _log_page("/wp-login.php?action=logout")
    session.clear()
    resp = make_response(redirect("/wp-login.php?loggedout=true"))
    resp.delete_cookie("wordpress_logged_in_abc123")
    resp.delete_cookie("wordpress_sec_abc123")
    return resp


# ── xmlrpc.php (honeypot endpoint) ───────────────────────────────────────────

@wp.route("/xmlrpc.php", methods=["GET", "POST"])
def wp_xmlrpc():
    _log_page("/xmlrpc.php")
    if request.method == "GET":
        return ("XML-RPC server accepts POST requests only.", 405)
    body = request.get_data(as_text=True)
    send_log(SERVICE_ID, {
        "ip": _ip(),
        "request_type": "other_form",
        "method": "POST",
        "path": "/xmlrpc.php",
        "user_agent": _ua(),
        "form_data": {"body": body[:500]},
        "status_code": 200,
        "response_size": 0,
    })
    return ("""<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><boolean>1</boolean></value></param></params></methodResponse>""",
            200, {"Content-Type": "application/xml"})


# ── wp-cron.php ───────────────────────────────────────────────────────────────

@wp.route("/wp-cron.php", methods=["GET"])
def wp_cron():
    _log_page("/wp-cron.php")
    return ("", 200)


# ── wp-json API stubs ─────────────────────────────────────────────────────────

@wp.route("/wp-json/", methods=["GET"])
@wp.route("/wp-json/wp/v2/", methods=["GET"])
def wp_json_root():
    _log_page(request.path)
    import json as _json
    data = {
        "name": "My WordPress Site",
        "description": "Just another WordPress site",
        "url": "http://localhost",
        "home": "http://localhost",
        "namespaces": ["oembed/1.0", "wp/v2"],
        "authentication": {},
        "routes": {
            "/wp/v2/posts": {"namespace": "wp/v2", "methods": ["GET", "POST"]},
            "/wp/v2/users": {"namespace": "wp/v2", "methods": ["GET", "POST"]},
            "/wp/v2/media": {"namespace": "wp/v2", "methods": ["GET", "POST"]},
        }
    }
    return (_json.dumps(data), 200, {"Content-Type": "application/json"})


@wp.route("/wp-json/wp/v2/posts", methods=["GET"])
def wp_json_posts():
    _log_page("/wp-json/wp/v2/posts")
    import json as _json
    posts = store.wp_get_posts()
    return (_json.dumps(posts), 200, {"Content-Type": "application/json"})


@wp.route("/wp-json/wp/v2/users", methods=["GET"])
def wp_json_users():
    _log_page("/wp-json/wp/v2/users")
    import json as _json
    users = store.wp_get_users()
    return (_json.dumps(users), 200, {"Content-Type": "application/json"})