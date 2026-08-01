import secrets
from flask import Flask, request, render_template_string, make_response, Response
from common.log_client import send_log

from config import (
    SERVICE_ID, TEMPLATE,
    brute_force_guard, rate_limit_guard,
    print_startup_info,
)
from template_utils import get_login_template, get_dashboard_template, get_login_fields
from credentials import extract_credentials, is_login_attempt, validate_credentials

app = Flask(__name__)

@app.before_request
def ignore_favicon():
    if request.path == "/favicon.ico":
        return Response(status=204)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    ip         = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    full_path  = f"/{path}" if path else "/"
    fields     = get_login_fields()
    login_html = get_login_template()

    if request.method == "GET":
        return _handle_get(ip, user_agent, full_path, login_html)

    return _handle_post(ip, user_agent, full_path, login_html, fields)


# ── Handlers internos ─────────────────────────────────────────────────────────

def _handle_get(ip, user_agent, full_path, login_html):
    if rate_limit_guard:
        rate_limit_guard.record_request(ip)

    send_log(SERVICE_ID, {
        "ip": ip,
        "request_type": "page_view",
        "method": "GET",
        "path": full_path,
        "user_agent": user_agent,
        "status_code": 200,
        "response_size": len(login_html.encode()),
    })

    return render_template_string(login_html, error=None), 200


def _handle_post(ip, user_agent, full_path, login_html, fields):
    form_data = dict(request.form)
    print(f"[http] POST {ip} {full_path} → {form_data}")

    if not is_login_attempt(form_data, fields):
        return _handle_other_form(ip, user_agent, full_path, login_html, form_data)

    return _handle_login(ip, user_agent, full_path, login_html, fields, form_data)


def _handle_login(ip, user_agent, full_path, login_html, fields, form_data):
    username, password = extract_credentials(form_data, fields)
    print(f"[http] Login attempt: {ip} user={username}")

    credentials_valid = validate_credentials(username, password)

    send_log(SERVICE_ID, {
        "ip": ip,
        "request_type": "login_attempt",
        "method": "POST",
        "path": full_path,
        "user_agent": user_agent,
        "username": username,
        "password": password,
        "login_success": credentials_valid,
        "status_code": 200 if credentials_valid else 403,
        "response_size": len(login_html.encode()),
    })

    if credentials_valid:
        return _build_success_response(username)

    brute_force_guard.record_attempt(
        ip=ip,
        username=username or "unknown",
        password=password or "unknown",
    )
    return render_template_string(login_html, error="Invalid username or password."), 403


def _build_success_response(username):
    dashboard_html  = get_dashboard_template()
    session_token   = secrets.token_hex(32)
    response        = make_response(render_template_string(dashboard_html, username=username), 200)

    cookie_defaults = dict(max_age=3600, secure=False, samesite="Lax")
    response.set_cookie("auth_token", session_token, httponly=True, **cookie_defaults)
    response.set_cookie("username",   username,                      **cookie_defaults)

    print(f"[http] Login exitoso para {username}")
    return response


def _handle_other_form(ip, user_agent, full_path, login_html, form_data):
    print(f"[http] Form submission (non-login): {ip} {full_path}")

    send_log(SERVICE_ID, {
        "ip": ip,
        "request_type": "other_form",
        "method": "POST",
        "path": full_path,
        "user_agent": user_agent,
        "form_data": form_data,
        "status_code": 400,
        "response_size": len(login_html.encode()),
    })

    return render_template_string(login_html, error="Invalid request"), 400



if __name__ == "__main__":
    print_startup_info()
    app.run(host="0.0.0.0", port=5000, debug=False)