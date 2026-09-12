# Copilot instructions for wifi-cert-manager

## What this is
CA / server / client certificate lifecycle manager for WiFi 802.1X (EAP-TLS)
authentication, deployed in front of a FreeRADIUS server. Ships a CLI
(`click`) and a Flask web UI, both backed by one shared library.

## Architecture (keep it this way)
- **`wifi_cert_manager/core.py`** - the ONLY place certificate logic, state
  I/O, and config loading live. All CA/cert creation, renewal, cascading
  reissue, expiry checks, PKCS#12/PEM export, and key-password handling go
  here. Never duplicate this logic in `cli.py` or `webapp/app.py` - they are
  thin wrappers that call into `CertStore`/`load_config`.
- **`wifi_cert_manager/cli.py`** - `click` CLI (`certmgr` entry point).
  Mirrors every `CertStore` operation. Reads defaults from `config.yaml`,
  supports per-invocation overrides on the top-level `main` group.
- **`wifi_cert_manager/webapp/app.py`** - Flask app factory + JSON API under
  `/api/*`. `templates/index.html` + `static/app.js` is a plain vanilla-JS
  page (no build step, no framework) that only talks to `/api/*`, so a
  richer SPA could replace it later without touching the backend.
- **State is flat files only - no database.** `data/state.json` (JSON
  index, written via `_transaction()` with `fcntl` file locking + atomic
  `os.replace`) plus PEM files under `data/ca/<name>/` and
  `data/certs/<name>/`. Don't introduce sqlite/postgres/etc.

## Conventions to follow
- Any new third-party dependency must be added to **both**
  `requirements.txt` and `pyproject.toml`'s `[project.dependencies]`.
- A cert/intermediate must never be allowed to outlive its issuing CA -
  `_check_not_after_within_issuer()` enforces this in `core.py`; don't
  bypass it when adding new issuance paths.
- Private keys may optionally be password-encrypted
  (`serialization.BestAvailableEncryption`). The password itself is never
  persisted - only a `key_encrypted: bool` flag in `state.json`. CLI/web UI
  must always require double-entry confirmation when a human is setting a
  new key password (see `_resolve_key_password` in `cli.py` and
  `_confirmed_password` in `webapp/app.py`).
- Config precedence: `config.yaml` (or `WCM_CONFIG` env path) → `WCM_*`
  env var overrides → explicit CLI flags / API call args, in that order.
- Keep `README.md` (rendered live in the web UI's "Readme" tab via
  `/api/readme`) up to date when behavior changes - it's the primary user
  doc, including the FreeRADIUS deployment and troubleshooting guidance.

## Running / testing locally
```sh
pip install -r requirements.txt -e .
cp config.example.yaml config.yaml
certmgr status
python -m wifi_cert_manager.webapp.app   # http://localhost:8080
```

## Docker
`docker compose up -d --build`. The image runs as root initially so
`docker-entrypoint.sh` can `chown` the bind-mounted `/data` volume for
whatever host UID owns it, then drops to the unprivileged `certmgr` user via
`gosu` before exec'ing the real command (`gunicorn` by default, or
`certmgr ...` when overridden). Keep this drop-privilege pattern if you
touch the Dockerfile/entrypoint - don't just run the container as root.

## Security notes
- Private key files are written with mode `0600`.
- Never log or persist plaintext private key passwords.
- Validate all names (`_validate_name`) before using them as filesystem
  path components - they come from user input (CLI args / API JSON).
