"""Click-based command line interface for wifi-cert-manager.

Thin wrapper around wifi_cert_manager.core - all real logic lives there so
the CLI and the web UI stay in sync. Configuration comes from config.yaml
(see load_config), with the options on the top-level command available to
override individual values for a single invocation.
"""
from __future__ import annotations

import dataclasses
import pathlib
import sys

import click

from wifi_cert_manager.core import (
    CertManagerError,
    CertStore,
    load_config,
)

# Global config overrides: (CLI flag, Config field name, value type)
CONFIG_OVERRIDES = [
    ("--data-dir", "data_dir", str),
    ("--key-size", "key_size", int),
    ("--digest", "digest", str),
    ("--ca-days", "ca_valid_days", int),
    ("--intermediate-days", "intermediate_valid_days", int),
    ("--server-days", "server_valid_days", int),
    ("--client-days", "client_valid_days", int),
    ("--country", "country", str),
    ("--state", "state_name", str),
    ("--locality", "locality", str),
    ("--org", "org", str),
    ("--org-unit", "org_unit", str),
    ("--email", "email", str),
    ("--expiry-warning-days", "expiry_warning_days", int),
    ("--expiry-critical-days", "expiry_critical_days", int),
]


def _add_config_overrides(fn):
    for flag, field, _type in reversed(CONFIG_OVERRIDES):
        fn = click.option(flag, field, default=None, type=_type, help=f"Override config.yaml's '{field}'")(fn)
    return fn


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@_add_config_overrides
@click.pass_context
def main(ctx: click.Context, config_path: str | None, **overrides) -> None:
    """Manage CA, server and client certificates for WiFi TLS authentication.

    Settings are read from config.yaml (or WCM_CONFIG/WCM_* env vars); use
    the options below to override individual values for this invocation.
    """
    ctx.ensure_object(dict)
    cfg = load_config(config_path)
    changes = {k: v for k, v in overrides.items() if v is not None}
    if changes:
        cfg = dataclasses.replace(cfg, **changes)
    ctx.obj["store"] = CertStore(cfg)


def _store(ctx: click.Context) -> CertStore:
    return ctx.obj["store"]


def _fail(message: str) -> None:
    click.secho(f"Error: {message}", fg="red", err=True)
    sys.exit(1)


def _level_color(level: str) -> str:
    return {"ok": "green", "warning": "yellow", "critical": "red", "expired": "red"}.get(level, "white")


SUBJECT_OPTIONS = [
    click.option("--country", default=None, help="Subject country (C)"),
    click.option("--state", "state_name", default=None, help="Subject state/province (ST)"),
    click.option("--locality", default=None, help="Subject locality (L)"),
    click.option("--org", default=None, help="Subject organization (O)"),
    click.option("--org-unit", default=None, help="Subject organizational unit (OU)"),
    click.option("--email", default=None, help="Subject email address"),
]


def add_subject_options(fn):
    for opt in reversed(SUBJECT_OPTIONS):
        fn = opt(fn)
    return fn


def build_subject(**kwargs) -> dict:
    return {k: v for k, v in kwargs.items() if v is not None}


# --------------------------------------------------------------------------
# CA commands
# --------------------------------------------------------------------------
@main.group()
def ca() -> None:
    """Create, import, renew and list Certificate Authorities."""


@ca.command("create")
@click.argument("name")
@click.option("--cn", "common_name", required=True, help="Common name for the CA")
@click.option("--intermediate-of", default=None, help="Name of an existing CA to sign this as an intermediate")
@click.option("--days", type=int, default=None, help="Validity period in days")
@click.option("--key-size", type=int, default=None, help="RSA key size")
@add_subject_options
@click.pass_context
def ca_create(ctx, name, common_name, intermediate_of, days, key_size, **subject_kwargs) -> None:
    """Create a new root CA, or an intermediate signed by an existing CA."""
    try:
        entry = _store(ctx).create_ca(
            name,
            common_name,
            intermediate_of=intermediate_of,
            days=days,
            key_size=key_size,
            subject=build_subject(**subject_kwargs),
        )
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Created CA '{entry['name']}' ({entry['type']}), valid until {entry['not_after']}")


@ca.command("import")
@click.argument("name")
@click.option("--cert", "cert_file", required=True, type=click.File("rb"), help="PEM certificate file")
@click.option("--key", "key_file", default=None, type=click.File("rb"), help="PEM private key file (optional)")
@click.pass_context
def ca_import(ctx, name, cert_file, key_file) -> None:
    """Import an existing CA/intermediate certificate (and optionally its key)."""
    try:
        entry = _store(ctx).import_ca(name, cert_file.read(), key_file.read() if key_file else None)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Imported CA '{entry['name']}' (key available: {entry['key_available']})")


@ca.command("renew")
@click.argument("name")
@click.option("--cascade/--no-cascade", default=True, help="Also reissue all downstream certs signed by this CA")
@click.pass_context
def ca_renew(ctx, name, cascade) -> None:
    """Renew (regenerate key+cert for) a CA, cascading to downstream certs by default."""
    try:
        result = _store(ctx).renew_ca(name, cascade=cascade)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Renewed CA '{name}', valid until {result['ca']['not_after']}")
    if result["reissued"]:
        click.echo("Reissued downstream: " + ", ".join(result["reissued"]))


@ca.command("list")
@click.pass_context
def ca_list(ctx) -> None:
    """List all CAs with expiry status."""
    dash = _store(ctx).dashboard()
    for entry in dash["cas"]:
        click.secho(
            f"{entry['name']:<20} {entry['type']:<12} days_left={entry['days_left']:<6} "
            f"not_after={entry['not_after']}",
            fg=_level_color(entry["level"]),
        )


@ca.command("revoke")
@click.argument("name")
@click.pass_context
def ca_revoke(ctx, name) -> None:
    """Mark a CA as revoked (does not delete files)."""
    try:
        _store(ctx).revoke_ca(name)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"CA '{name}' marked as revoked")


@ca.command("crl")
@click.argument("name")
@click.option("--out", "out_file", type=click.File("wb"), default=None, help="Write CRL PEM to this file")
@click.pass_context
def ca_crl(ctx, name, out_file) -> None:
    """Generate/refresh the CRL for a CA (covers certs revoked via 'cert revoke')."""
    try:
        crl_bytes = _store(ctx).generate_crl(name)
    except CertManagerError as exc:
        _fail(str(exc))
    if out_file:
        out_file.write(crl_bytes)
    else:
        click.echo(crl_bytes.decode())


# --------------------------------------------------------------------------
# server / client cert commands
# --------------------------------------------------------------------------
def _resolve_key_password(key_password: str | None, ask_key_password: bool) -> str | None:
    """Return the password to encrypt/decrypt a private key with, prompting
    twice (and requiring the entries to match) when --ask-key-password is
    used. Always optional: blank input means no password."""
    if ask_key_password:
        entered = click.prompt(
            "Private key password (leave blank for none)",
            hide_input=True,
            confirmation_prompt="Repeat private key password",
            default="",
            show_default=False,
        )
        return entered or None
    return key_password or None


KEY_PASSWORD_OPTIONS = [
    click.option(
        "--key-password", default=None,
        help="Encrypt the private key with this password (e.g. to match FreeRADIUS's private_key_password); "
        "omit for no password",
    ),
    click.option(
        "--ask-key-password", is_flag=True, default=False,
        help="Interactively prompt for the private key password (entered twice, must match) instead of --key-password",
    ),
]


def add_key_password_options(fn):
    for opt in reversed(KEY_PASSWORD_OPTIONS):
        fn = opt(fn)
    return fn


def _issue(ctx, kind, name, ca_name, common_name, sans, days, key_size, subject_kwargs, key_password) -> None:
    try:
        entry = _store(ctx).issue_cert(
            kind,
            ca_name,
            name,
            common_name,
            sans=list(sans) if sans else None,
            days=days,
            key_size=key_size,
            subject=build_subject(**subject_kwargs),
            key_password=key_password,
        )
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Issued {kind} certificate '{entry['name']}' signed by '{ca_name}', valid until {entry['not_after']}")


@main.group()
def server() -> None:
    """Create/manage server certificates (used by FreeRADIUS)."""


@server.command("create")
@click.argument("name")
@click.option("--ca", "ca_name", required=True, help="Issuing CA name")
@click.option("--cn", "common_name", required=True, help="Server common name (e.g. radius.example.com)")
@click.option("--san", "sans", multiple=True, help="Subject alternative name (DNS or IP), repeatable")
@click.option("--days", type=int, default=None)
@click.option("--key-size", type=int, default=None)
@add_subject_options
@add_key_password_options
@click.pass_context
def server_create(ctx, name, ca_name, common_name, sans, days, key_size, key_password, ask_key_password, **subject_kwargs) -> None:
    """Issue a new server certificate."""
    resolved = _resolve_key_password(key_password, ask_key_password)
    _issue(ctx, "server", name, ca_name, common_name, sans, days, key_size, subject_kwargs, resolved)


@main.group()
def client() -> None:
    """Create/manage client certificates (used for EAP-TLS supplicants)."""


@client.command("create")
@click.argument("name")
@click.option("--ca", "ca_name", required=True, help="Issuing CA name")
@click.option("--cn", "common_name", required=True, help="Client common name (e.g. user or device identity)")
@click.option("--days", type=int, default=None)
@click.option("--key-size", type=int, default=None)
@add_subject_options
@add_key_password_options
@click.pass_context
def client_create(ctx, name, ca_name, common_name, days, key_size, key_password, ask_key_password, **subject_kwargs) -> None:
    """Issue a new client certificate."""
    resolved = _resolve_key_password(key_password, ask_key_password)
    _issue(ctx, "client", name, ca_name, common_name, (), days, key_size, subject_kwargs, resolved)


# --------------------------------------------------------------------------
# generic cert commands (apply to both server and client certs)
# --------------------------------------------------------------------------
@main.group()
def cert() -> None:
    """Operate on any previously issued server/client certificate."""


@cert.command("list")
@click.pass_context
def cert_list(ctx) -> None:
    """List all issued certificates with expiry status."""
    dash = _store(ctx).dashboard()
    for entry in dash["certs"]:
        click.secho(
            f"{entry['name']:<20} {entry['kind']:<8} issuer={entry['issuer']:<16} "
            f"days_left={entry['days_left']:<6} not_after={entry['not_after']}",
            fg=_level_color(entry["level"]),
        )


@cert.command("reissue")
@click.argument("name")
@add_key_password_options
@click.pass_context
def cert_reissue(ctx, name, key_password, ask_key_password) -> None:
    """Regenerate a certificate's key+cert, signed by its current issuing CA."""
    resolved = _resolve_key_password(key_password, ask_key_password)
    try:
        entry = _store(ctx).reissue_cert(name, key_password=resolved)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Reissued '{name}', valid until {entry['not_after']}")


@cert.command("revoke")
@click.argument("name")
@click.pass_context
def cert_revoke(ctx, name) -> None:
    """Mark a certificate as revoked (run 'ca crl' afterwards to publish it)."""
    try:
        _store(ctx).revoke_cert(name)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Certificate '{name}' marked as revoked")


@cert.command("delete")
@click.argument("name")
@click.confirmation_option(prompt="Really delete this certificate and its key material?")
@click.pass_context
def cert_delete(ctx, name) -> None:
    """Delete a certificate's files and remove it from the store."""
    try:
        _store(ctx).delete_cert(name)
    except CertManagerError as exc:
        _fail(str(exc))
    click.echo(f"Deleted '{name}'")


@cert.command("export")
@click.argument("name")
@click.option("--out", "out_file", type=click.File("wb"), required=True, help="Output .p12 file")
@click.option("--password", default=None, help="PKCS#12 password (omit for none)")
@click.option("--key-password", default=None, help="Password to decrypt the stored private key, if it has one")
@click.pass_context
def cert_export(ctx, name, out_file, password, key_password) -> None:
    """Export a certificate + key + CA chain as a PKCS#12 (.p12) bundle."""
    try:
        data = _store(ctx).export_pkcs12(name, password, key_password=key_password)
    except CertManagerError as exc:
        _fail(str(exc))
    out_file.write(data)
    click.echo(f"Exported '{name}' to {out_file.name}")


@cert.command("bundle")
@click.argument("name")
@click.option(
    "--out-dir", "out_dir", type=click.Path(file_okay=False, writable=True), required=True,
    help="Directory to write <name>.crt, <name>.key and ca.pem into",
)
@click.pass_context
def cert_bundle(ctx, name, out_dir) -> None:
    """Write plain PEM cert/key/ca-chain files, e.g. for FreeRADIUS's eap.conf
    certificate_file / private_key_file / ca_file settings."""
    try:
        bundle = _store(ctx).export_pem_bundle(name)
    except CertManagerError as exc:
        _fail(str(exc))
    out_path = pathlib.Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / f"{name}.crt").write_bytes(bundle["cert_pem"])
    (out_path / f"{name}.key").write_bytes(bundle["key_pem"])
    (out_path / f"{name}.key").chmod(0o600)
    (out_path / "ca.pem").write_bytes(bundle["chain_pem"])
    click.echo(f"Wrote {name}.crt, {name}.key and ca.pem to {out_path}")


# --------------------------------------------------------------------------
# dashboard / status
# --------------------------------------------------------------------------
@main.command()
@click.pass_context
def status(ctx) -> None:
    """Show an expiry overview for all CAs and certificates."""
    dash = _store(ctx).dashboard()
    click.echo("== Certificate Authorities ==")
    for entry in dash["cas"]:
        click.secho(
            f"{entry['name']:<20} {entry['type']:<12} days_left={entry['days_left']:<6} "
            f"level={entry['level']:<8} not_after={entry['not_after']}",
            fg=_level_color(entry["level"]),
        )
    click.echo("== Server/Client Certificates ==")
    for entry in dash["certs"]:
        click.secho(
            f"{entry['name']:<20} {entry['kind']:<8} issuer={entry['issuer']:<16} "
            f"days_left={entry['days_left']:<6} level={entry['level']:<8} not_after={entry['not_after']}",
            fg=_level_color(entry["level"]),
        )
    if dash["worst_level"] != "ok":
        click.secho(f"\nOverall status: {dash['worst_level'].upper()}", fg=_level_color(dash["worst_level"]), bold=True)
        sys.exit(1 if dash["worst_level"] in ("critical", "expired") else 0)


if __name__ == "__main__":
    main()
