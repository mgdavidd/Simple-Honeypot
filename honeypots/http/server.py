import secrets
from flask import Flask, request, render_template, make_response, redirect, url_for, Response, session
from common.log_client import send_log

from config import (
    SERVICE_ID, TEMPLATE,
    brute_force_guard, rate_limit_guard,
    print_startup_info,
)
from template_utils import get_login_fields
from credentials import extract_credentials, is_login_attempt, validate_credentials

# Importar blueprints según template
from routes_wordpress import wp
from routes_phpmyadmin import pma

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── Registrar blueprints ───────────────────────────────────────────────────────
app.register_blueprint(wp)
app.register_blueprint(pma)


@app.before_request
def ignore_favicon():
    if request.path == "/favicon.ico":
        return Response(status=204)


@app.before_request
def rate_limit_check():
    if rate_limit_guard and request.method == "GET":
        rate_limit_guard.record_request(request.remote_addr)


# ── Ruta raíz: redirigir según template ───────────────────────────────────────
@app.route("/")
def index():
    if TEMPLATE == "wordpress":
        return redirect("/wp-login.php")
    elif TEMPLATE == "phpmyadmin":
        return redirect("/phpmyadmin/")
    return redirect("/wp-login.php")


# ── Catch-all para rutas no definidas: log y 404 ──────────────────────────────
@app.errorhandler(404)
def not_found(e):
    ip = request.remote_addr
    send_log(SERVICE_ID, {
        "ip": ip,
        "request_type": "page_view",
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "status_code": 404,
        "response_size": 0,
    })
    if TEMPLATE == "wordpress":
        return render_template("wp_404.html"), 404
    return render_template("pma_404.html"), 404


if __name__ == "__main__":
    print_startup_info()
    app.run(host="0.0.0.0", port=5000, debug=False)