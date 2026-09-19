"""Flask web UI + JSON API for wifi-cert-manager.

The UI (templates/index.html + static/app.js) is a simple server-rendered
page that talks to the JSON endpoints under /api/*. Keeping the API separate
from the page means a richer SPA framework can be swapped in later without
touching wifi_cert_manager.core.
"""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import markdown
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

from wifi_cert_manager.core import (
    CertManagerError,
    CertStore,
    NotFoundError,
    ValidationError,
    load_config,
)
from wifi_cert_manager.webapp.auth import bp as auth_bp, init_oauth, require_login


def _find_readme() -> Path | None:
    # Repo checkout: wifi_cert_manager/webapp/app.py -> repo root. Container:
    # README.md is copied to the working directory alongside config.yaml.
    candidates = [
        Path.cwd() / "README.md",
        Path(__file__).resolve().parents[2] / "README.md",
    ]
    return next((c for c in candidates if c.is_file()), None)


def _confirmed_password(body: dict, field: str) -> str | None:
    """Require `<field>` and `<field>_confirm` to match when either is set;
    an optional password is meaningless if a typo could lock you out of it."""
    value = body.get(field) or None
    confirm = body.get(f"{field}_confirm") or None
    if value != confirm:
        raise ValidationError(f"'{field}' and '{field}_confirm' do not match")
    return value


def create_app(config=None) -> Flask:
    app = Flask(__name__)
    # Trust X-Forwarded-* from the reverse proxy so url_for(_external=True)
    # (used to build the OIDC redirect_uri) sees the real scheme/host.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    cfg = config or load_config()
    store = CertStore(cfg)
    app.config["STORE"] = store
    app.secret_key = cfg.secret_key or os.environ.get("SECRET_KEY") or os.urandom(32)
    init_oauth(app)
    app.register_blueprint(auth_bp)
    app.before_request(require_login)

    @app.errorhandler(CertManagerError)
    def _handle_error(err: CertManagerError):
        status = 404 if isinstance(err, NotFoundError) else 400
        return jsonify({"error": str(err)}), status

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/readme")
    def api_readme():
        readme_path = _find_readme()
        if not readme_path:
            return "<p>README.md not found.</p>", 404, {"Content-Type": "text/html; charset=utf-8"}
        html = markdown.markdown(
            readme_path.read_text(), extensions=["fenced_code", "tables", "sane_lists"]
        )
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    # ---- dashboard ----------------------------------------------------------
    @app.get("/api/dashboard")
    def api_dashboard():
        return jsonify(store.dashboard())

    # ---- CAs ------------------------------------------------------------------
    @app.get("/api/cas")
    def api_ca_list():
        return jsonify(store.list_cas())

    @app.post("/api/cas")
    def api_ca_create():
        body = request.get_json(force=True)
        entry = store.create_ca(
            body["name"],
            body["common_name"],
            intermediate_of=body.get("intermediate_of") or None,
            days=body.get("days"),
            key_size=body.get("key_size"),
            subject=body.get("subject"),
        )
        return jsonify(entry), 201

    @app.post("/api/cas/import")
    def api_ca_import():
        name = request.form["name"]
        cert_file = request.files["cert"]
        key_file = request.files.get("key")
        entry = store.import_ca(name, cert_file.read(), key_file.read() if key_file else None)
        return jsonify(entry), 201

    @app.get("/api/cas/<name>")
    def api_ca_get(name):
        return jsonify(store.get_ca(name))

    @app.post("/api/cas/<name>/renew")
    def api_ca_renew(name):
        body = request.get_json(silent=True) or {}
        result = store.renew_ca(name, cascade=body.get("cascade", True))
        return jsonify(result)

    @app.post("/api/cas/<name>/revoke")
    def api_ca_revoke(name):
        store.revoke_ca(name)
        return jsonify({"ok": True})

    @app.get("/api/cas/<name>/crl")
    def api_ca_crl(name):
        crl_bytes = store.generate_crl(name)
        return send_file(io.BytesIO(crl_bytes), mimetype="application/x-pem-file", download_name=f"{name}.crl.pem")

    @app.get("/api/cas/<name>/download")
    def api_ca_download(name):
        entry = store.get_ca(name)
        data = store.read_file(entry["chain_file"])
        return send_file(io.BytesIO(data), mimetype="application/x-pem-file", download_name=f"{name}.chain.pem")

    # ---- certs (server + client) ---------------------------------------------
    @app.get("/api/certs")
    def api_cert_list():
        kind = request.args.get("kind")
        certs = store.list_certs()
        if kind:
            certs = [c for c in certs if c["kind"] == kind]
        return jsonify(certs)

    @app.post("/api/certs")
    def api_cert_create():
        body = request.get_json(force=True)
        key_password = _confirmed_password(body, "key_password")
        entry = store.issue_cert(
            body["kind"],
            body["ca_name"],
            body["name"],
            body["common_name"],
            sans=body.get("sans"),
            days=body.get("days"),
            key_size=body.get("key_size"),
            subject=body.get("subject"),
            key_password=key_password,
        )
        return jsonify(entry), 201

    @app.get("/api/certs/<name>")
    def api_cert_get(name):
        return jsonify(store.get_cert(name))

    @app.post("/api/certs/<name>/reissue")
    def api_cert_reissue(name):
        body = request.get_json(silent=True) or {}
        key_password = _confirmed_password(body, "key_password")
        return jsonify(store.reissue_cert(name, key_password=key_password))

    @app.post("/api/certs/<name>/revoke")
    def api_cert_revoke(name):
        store.revoke_cert(name)
        return jsonify({"ok": True})

    @app.delete("/api/certs/<name>")
    def api_cert_delete(name):
        store.delete_cert(name)
        return jsonify({"ok": True})

    @app.get("/api/certs/<name>/export")
    def api_cert_export(name):
        password = request.args.get("password") or None
        key_password = request.args.get("key_password") or None
        data = store.export_pkcs12(name, password, key_password=key_password)
        return send_file(io.BytesIO(data), mimetype="application/x-pkcs12", download_name=f"{name}.p12")

    @app.get("/api/certs/<name>/bundle")
    def api_cert_bundle(name):
        # Plain PEM cert/key/ca-chain, e.g. for FreeRADIUS's eap.conf
        # certificate_file / private_key_file / ca_file settings.
        bundle = store.export_pem_bundle(name)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(f"{name}.crt", bundle["cert_pem"])
            zf.writestr(f"{name}.key", bundle["key_pem"])
            zf.writestr("ca.pem", bundle["chain_pem"])
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", download_name=f"{name}-bundle.zip")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
