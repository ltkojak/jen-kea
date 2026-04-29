"""
jen/__init__.py
───────────────
Application factory. Creates the Flask app, initialises all
extensions, registers blueprints, and wires up global middleware.

Usage:
    from jen import create_app
    app = create_app()
"""

import logging
import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, request, session, url_for
from flask_login import (LoginManager, current_user, login_required,
                         logout_user)

from jen import extensions
from jen.config import init_extensions_from_config, load_config, ssl_configured
from jen.models.user import User, audit, get_global_setting

logger = logging.getLogger(__name__)

JEN_VERSION = "3.2.6"

# Cache ssl_configured result — cert files don't change at runtime
_ssl_configured_cache: bool | None = None

def _ssl_configured_cached() -> bool:
    global _ssl_configured_cache
    if _ssl_configured_cache is None:
        _ssl_configured_cache = ssl_configured()
    return _ssl_configured_cache

# ── Login manager (module-level so decorators can reference it) ───────────────
login_manager = LoginManager()


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    Loads config, initialises all globals, registers every blueprint.
    """
    # ── Config & globals ──────────────────────────────────────────────────────
    cfg = load_config()
    init_extensions_from_config(cfg)

    # ── Flask app ─────────────────────────────────────────────────────────────
    app = Flask(__name__,
                static_folder="/opt/jen/static",
                template_folder="/opt/jen/templates")
    app.secret_key = _load_secret_key()

    # ── Login manager ─────────────────────────────────────────────────────────
    login_manager.init_app(app)
    login_manager.login_view    = "auth.login"
    login_manager.login_message = "Please log in to access Jen."

    @login_manager.user_loader
    def load_user(user_id):
        from flask import g as _g

        # Fast path: check g cache first (within same request)
        cached = getattr(_g, '_cached_user', None)
        if cached is not None and str(cached.id) == str(user_id):
            return cached

        # Fast path: reconstruct from session data if available
        # This avoids a DB round trip on every authenticated request.
        # Session is signed with SECRET_KEY so it can't be tampered with.
        sess_user = session.get('_user_cache')
        if sess_user and str(sess_user.get('id')) == str(user_id):
            user = User(
                sess_user['id'], sess_user['username'],
                sess_user['role'], sess_user.get('session_timeout')
            )
            _g._cached_user = user
            try: _g._route_start = __import__('time').time()
            except: pass
            return user

        # Slow path: DB lookup (only on first login or if session cache missing)
        from jen.models.db import get_jen_db
        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "SELECT id, username, role, session_timeout FROM users WHERE id=%s",
                    (user_id,)
                )
                row = cur.fetchone()
            db.close()
            if row:
                user = User(row["id"], row["username"],
                            row["role"], row["session_timeout"])
                # Cache in session for future requests (no DB hit)
                session['_user_cache'] = {
                    'id': row["id"], 'username': row["username"],
                    'role': row["role"], 'session_timeout': row["session_timeout"]
                }
                _g._cached_user = user
                try: _g._route_start = __import__('time').time()
                except: pass
                return user
        except Exception as e:
            logger.error(f"load_user error: {e}")
        return None

    # ── Middleware ────────────────────────────────────────────────────────────
    @app.before_request
    def _time_request_start():
        import time
        from flask import g
        g._request_start = time.time()
        g._after_load_user = time.time()  # overwritten by load_user

    @app.after_request
    def _time_request_end(response):
        import time
        from flask import g
        if hasattr(g, '_request_start') and not request.path.startswith('/static/'):
            elapsed = (time.time() - g._request_start) * 1000
            if elapsed > 500:
                import logging
                logging.getLogger('jen.timing').warning(
                    f"SLOW {elapsed:.0f}ms  {request.method} {request.path}"
                )
        return response

    @app.before_request
    def check_session_timeout():
        if not current_user.is_authenticated:
            return
        # Skip static assets entirely
        if request.path.startswith('/static/'):
            return
        if get_global_setting("session_timeout_enabled", "true") == "false":
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            return
        timeout = current_user.session_timeout or int(
            get_global_setting("session_timeout_minutes", "60")
        )
        if int(timeout) == 0:
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            return
        now  = datetime.now(timezone.utc)
        last = session.get("last_active")
        if not last:
            session["last_active"] = now.isoformat()
        else:
            try:
                elapsed = (now - datetime.fromisoformat(last)).total_seconds() / 60
                if elapsed > int(timeout):
                    logout_user()
                    flash("Session expired. Please log in again.", "error")
                    return redirect(url_for("auth.login"))
            except Exception:
                pass
            if not request.path.startswith("/api/") and request.path != "/metrics":
                session["last_active"] = now.isoformat()

    @app.before_request
    def redirect_to_https():
        if request.is_secure:
            return
        if _ssl_configured_cached() and not request.is_secure:
            host = request.host.split(":")[0]
            return redirect(
                f"https://{host}:{extensions.HTTPS_PORT}{request.path}",
                code=301
            )

    # ── Context processor ─────────────────────────────────────────────────────
    @app.context_processor
    def inject_branding():
        avatar_url   = None
        nav_logo_url = None
        if current_user and current_user.is_authenticated:
            # Cache avatar in session — only query DB when not yet cached
            avatar_url = session.get("_avatar_url", "__unset__")
            if avatar_url == "__unset__":
                try:
                    from jen.models.db import get_jen_db
                    db = get_jen_db()
                    with db.cursor() as cur:
                        cur.execute("SELECT avatar_url FROM users WHERE id=%s",
                                    (current_user.id,))
                        row = cur.fetchone()
                        avatar_url = row.get("avatar_url") if row else None
                    db.close()
                except Exception:
                    avatar_url = None
                session["_avatar_url"] = avatar_url
        nav_logo_path = extensions.NAV_LOGO_PATH
        for ext in ("png", "svg", "jpg", "jpeg", "webp"):
            path = f"{nav_logo_path}.{ext}"
            if os.path.exists(path):
                nav_logo_url = f"/static/nav_logo.{ext}?v={int(os.path.getmtime(path))}"
                break
        return {
            "branding_name":       "Jen",
            "branding_nav_color":  get_global_setting("branding_nav_color", ""),
            "branding_nav_logo":   nav_logo_url,
            "current_user_avatar": avatar_url,
            "jen_version":         JEN_VERSION,
        }

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template("error.html", code=500,
                               message="Internal server error."), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        from flask import render_template
        logger.exception(f"Unhandled exception: {e}")
        return render_template("error.html", code=500,
                               message=f"An error occurred: {e}"), 500

    # ── Favicon ───────────────────────────────────────────────────────────────
    @app.route("/favicon.ico")
    def favicon():
        from flask import send_from_directory
        if os.path.exists(extensions.FAVICON_PATH):
            return send_from_directory(extensions.STATIC_DIR, "favicon.ico")
        return "", 204

    # ── Blueprints ────────────────────────────────────────────────────────────
    _register_blueprints(app)

    # ── DB init ───────────────────────────────────────────────────────────────
    from jen.models.db import init_jen_db
    init_jen_db()

    return app


def admin_required(f):
    """Decorator — restricts route to admin users."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)
    return decorated


def _register_blueprints(app: Flask) -> None:
    """Import and register all route blueprints."""
    from jen.routes.api       import bp as api_bp
    from jen.routes.auth      import bp as auth_bp
    from jen.routes.dashboard import bp as dashboard_bp
    from jen.routes.ddns      import bp as ddns_bp
    from jen.routes.devices   import bp as devices_bp
    from jen.routes.leases    import bp as leases_bp
    from jen.routes.mfa_routes import bp as mfa_bp
    from jen.routes.reports   import bp as reports_bp
    from jen.routes.reservations import bp as reservations_bp
    from jen.routes.search    import bp as search_bp
    from jen.routes.servers   import bp as servers_bp
    from jen.routes.settings  import bp as settings_bp
    from jen.routes.subnets   import bp as subnets_bp
    from jen.routes.users     import bp as users_bp

    for blueprint in [
        api_bp, auth_bp, dashboard_bp, ddns_bp, devices_bp,
        leases_bp, mfa_bp, reports_bp, reservations_bp, search_bp,
        servers_bp, settings_bp, subnets_bp, users_bp,
    ]:
        app.register_blueprint(blueprint)


def _load_secret_key() -> str:
    key_file = "/etc/jen/secret_key"
    try:
        if os.path.exists(key_file):
            with open(key_file) as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
        key = os.urandom(32).hex()
        os.makedirs("/etc/jen", exist_ok=True)
        with open(key_file, "w") as f:
            f.write(key)
        os.chmod(key_file, 0o640)
        return key
    except Exception as e:
        logger.warning(f"Could not persist secret key: {e}")
        return os.urandom(32).hex()
