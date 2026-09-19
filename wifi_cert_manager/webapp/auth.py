"""OIDC login against Authentik (or any OIDC provider) via Authlib.

Disabled by default (`oidc_enabled: false`); when off, `create_app` never
registers this blueprint's login gate and the app behaves as before.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for
from authlib.integrations.flask_client import OAuth

oauth = OAuth()
bp = Blueprint("auth", __name__)


def init_oauth(app) -> None:
    cfg = app.config["STORE"].config
    if not cfg.oidc_enabled:
        return
    oauth.init_app(app)
    oauth.register(
        name="authentik",
        server_metadata_url=cfg.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_id=cfg.oidc_client_id,
        client_secret=cfg.oidc_client_secret,
        client_kwargs={"scope": "openid email profile"},
    )


def _allowed(email: str) -> bool:
    cfg = current_app.config["STORE"].config
    allowed = [u.strip().lower() for u in cfg.oidc_allowed_users.split(",") if u.strip()]
    return not allowed or (email or "").lower() in allowed


def require_login() -> "tuple | None":
    """Call from a `before_request` hook. Returns a response to short-circuit
    the request, or None to let it proceed."""
    cfg = current_app.config["STORE"].config
    if not cfg.oidc_enabled:
        return None
    if request.endpoint in ("auth.login", "auth.callback", "static"):
        return None
    if "user" not in session:
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("auth.login"))
    return None


@bp.route("/login")
def login():
    redirect_uri = url_for("auth.callback", _external=True)
    return oauth.authentik.authorize_redirect(redirect_uri)


@bp.route("/auth/callback")
def callback():
    token = oauth.authentik.authorize_access_token()
    userinfo = token.get("userinfo") or oauth.authentik.userinfo(token=token)
    email = userinfo.get("email", "")
    if not _allowed(email):
        session.clear()
        return "Access denied: user is not on the allow list.", 403
    session["user"] = {
        "sub": userinfo.get("sub"),
        "email": email,
        "name": userinfo.get("name", email),
    }
    return redirect(url_for("index"))


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
