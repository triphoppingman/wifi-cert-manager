"""Centralized library for wifi-cert-manager.

Every certificate operation (create/import a CA or intermediate, issue server
and client certificates, renew, cascade-reissue downstream certs, check
expiry, export PKCS#12/PEM bundles) lives here so the CLI and the web UI are
both thin wrappers around the same code path.

State is intentionally kept in flat files only - no database engine:

    <data_dir>/state.json        # JSON metadata index (locked on writes)
    <data_dir>/ca/<name>/         # CA/intermediate key, cert and chain PEMs
    <data_dir>/certs/<name>/      # server/client key and cert PEMs

This makes the whole store a single directory that can be bind-mounted into
a container and backed up/restored trivially.
"""

from __future__ import annotations

import contextlib
import datetime
import fcntl
import ipaddress
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

STATE_FILENAME = "state.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

DEFAULT_CONFIG: dict[str, Any] = {
    "data_dir": "data",
    "key_size": 2048,
    "digest": "sha256",
    "ca_valid_days": 3650,
    "intermediate_valid_days": 1825,
    "server_valid_days": 825,
    "client_valid_days": 825,
    "country": "US",
    "state_name": "",
    "locality": "",
    "org": "WiFi Cert Manager",
    "org_unit": "",
    "email": "",
    "expiry_warning_days": 90,
    "expiry_critical_days": 30,
    "secret_key": "",
    "oidc_enabled": False,
    "oidc_issuer": "",
    "oidc_client_id": "",
    "oidc_client_secret": "",
    "oidc_allowed_users": "",
}


class CertManagerError(Exception):
    """Base error for all library operations."""


class NotFoundError(CertManagerError):
    """Raised when a named CA or certificate does not exist."""


class ValidationError(CertManagerError):
    """Raised for bad input or an operation that is not allowed."""


@dataclass
class Config:
    data_dir: str = "data"
    key_size: int = 2048
    digest: str = "sha256"
    ca_valid_days: int = 3650
    intermediate_valid_days: int = 1825
    server_valid_days: int = 825
    client_valid_days: int = 825
    country: str = "US"
    state_name: str = ""
    locality: str = ""
    org: str = "WiFi Cert Manager"
    org_unit: str = ""
    email: str = ""
    expiry_warning_days: int = 90
    expiry_critical_days: int = 30
    secret_key: str = ""
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_allowed_users: str = ""  # comma-separated emails; empty = allow anyone who logs in

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)


def load_config(path: Optional[str] = None) -> Config:
    """Load config.yaml (if present) merged with WCM_* environment overrides."""
    cfg = dict(DEFAULT_CONFIG)
    candidates = [path] if path else [
        os.environ.get("WCM_CONFIG"),
        "config.yaml",
        "/etc/wifi-cert-manager/config.yaml",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            with open(candidate) as fh:
                loaded = yaml.safe_load(fh) or {}
            cfg.update({k: v for k, v in loaded.items() if k in DEFAULT_CONFIG})
            break

    for key in list(cfg.keys()):
        env_key = f"WCM_{key.upper()}"
        if env_key in os.environ:
            raw = os.environ[env_key]
            if isinstance(cfg[key], bool):
                cfg[key] = raw.strip().lower() in ("1", "true", "yes", "on")
            elif isinstance(cfg[key], int):
                cfg[key] = int(raw)
            else:
                cfg[key] = raw

    return Config(**cfg)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise ValidationError(
            "Name must be 1-64 characters: letters, digits, '.', '_' or '-', "
            "and must not start with a symbol."
        )


def _digest_algorithm(name: str):
    algorithms = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
    try:
        return algorithms[name]
    except KeyError:
        raise ValidationError(f"Unsupported digest '{name}'") from None


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _build_name(subject: dict) -> x509.Name:
    attrs = []
    mapping = [
        ("country", NameOID.COUNTRY_NAME),
        ("state_name", NameOID.STATE_OR_PROVINCE_NAME),
        ("locality", NameOID.LOCALITY_NAME),
        ("org", NameOID.ORGANIZATION_NAME),
        ("org_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("email", NameOID.EMAIL_ADDRESS),
    ]
    for key, oid in mapping:
        value = subject.get(key)
        if value:
            attrs.append(x509.NameAttribute(oid, value))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject["common_name"]))
    return x509.Name(attrs)


def _key_usage(*, is_ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=not is_ca,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,
        crl_sign=is_ca,
        encipher_only=False,
        decipher_only=False,
    )


def _check_not_after_within_issuer(not_after: datetime.datetime, issuer_entry: dict, issuer_name: str) -> None:
    """A cert/intermediate must not outlive the CA that signs it - once the
    issuer expires (or is rotated), anything it signed stops validating too."""
    issuer_not_after = datetime.datetime.fromisoformat(issuer_entry["not_after"])
    if not_after > issuer_not_after:
        raise ValidationError(
            f"Requested validity (until {not_after.isoformat()}) would exceed issuing CA "
            f"'{issuer_name}'s own expiry ({issuer_not_after.isoformat()}). Shorten --days or renew "
            f"the CA first."
        )


@contextlib.contextmanager
def _locked(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

class CertStore:
    """Flat-file backed store for CAs and issued server/client certificates."""

    def __init__(self, config: Config):
        self.config = config
        self.root = config.data_path
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "ca").mkdir(exist_ok=True)
        (self.root / "certs").mkdir(exist_ok=True)
        self.state_path = self.root / STATE_FILENAME
        if not self.state_path.exists():
            self._write_state({"cas": {}, "certs": {}})

    # ---- low level state IO ------------------------------------------------
    def _read_state(self) -> dict:
        with open(self.state_path) as fh:
            return json.load(fh)

    def _write_state(self, state: dict) -> None:
        tmp = self.state_path.with_suffix(".json.tmp")
        with open(tmp, "w") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.state_path)

    @contextlib.contextmanager
    def _transaction(self):
        with _locked(self.state_path):
            state = self._read_state()
            yield state
            self._write_state(state)

    def _default_subject(self) -> dict:
        c = self.config
        return {
            "country": c.country,
            "state_name": c.state_name,
            "locality": c.locality,
            "org": c.org,
            "org_unit": c.org_unit,
            "email": c.email,
        }

    @staticmethod
    def _write_private_key(path: Path, key, password: Optional[str] = None) -> None:
        encryption = (
            serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        )
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            )
        )
        path.chmod(0o600)

    @staticmethod
    def _write_cert(path: Path, cert: x509.Certificate) -> None:
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _write_chain(self, state: dict, ca_dir: Path, parent: Optional[str]) -> None:
        chain_paths = [ca_dir / "ca.cert.pem"]
        cursor = parent
        while cursor:
            parent_entry = state["cas"][cursor]
            chain_paths.append(self.root / parent_entry["cert_file"])
            cursor = parent_entry.get("parent")
        data = b"".join(Path(p).read_bytes() for p in chain_paths)
        (ca_dir / "chain.pem").write_bytes(data)

    def _load_ca_key(self, name: str, state: dict):
        entry = state["cas"].get(name)
        if not entry:
            raise NotFoundError(f"CA '{name}' not found")
        if not entry.get("key_available"):
            raise ValidationError(f"CA '{name}' has no private key available")
        data = (self.root / entry["key_file"]).read_bytes()
        return serialization.load_pem_private_key(data, password=None)

    def _load_ca_cert(self, name: str, state: dict) -> x509.Certificate:
        entry = state["cas"].get(name)
        if not entry:
            raise NotFoundError(f"CA '{name}' not found")
        data = (self.root / entry["cert_file"]).read_bytes()
        return x509.load_pem_x509_certificate(data)

    # ---- CA lifecycle -------------------------------------------------------
    def create_ca(
        self,
        name: str,
        common_name: str,
        *,
        intermediate_of: Optional[str] = None,
        days: Optional[int] = None,
        key_size: Optional[int] = None,
        subject: Optional[dict] = None,
    ) -> dict:
        _validate_name(name)
        key_size = key_size or self.config.key_size
        subject = {**self._default_subject(), **(subject or {}), "common_name": common_name}

        with self._transaction() as state:
            if name in state["cas"]:
                raise ValidationError(f"CA '{name}' already exists")
            if intermediate_of:
                parent_entry = state["cas"].get(intermediate_of)
                if not parent_entry:
                    raise NotFoundError(f"Parent CA '{intermediate_of}' not found")
                if not parent_entry.get("key_available"):
                    raise ValidationError("Parent CA has no private key available to sign with")
                days = days or self.config.intermediate_valid_days
                _check_not_after_within_issuer(
                    _now() + datetime.timedelta(days=days), parent_entry, intermediate_of
                )
            else:
                days = days or self.config.ca_valid_days

            key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            ca_dir = self.root / "ca" / name
            ca_dir.mkdir(parents=True, exist_ok=True)

            builder = (
                x509.CertificateBuilder()
                .subject_name(_build_name(subject))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_now())
                .not_valid_after(_now() + datetime.timedelta(days=days))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0 if intermediate_of else None),
                    critical=True,
                )
                .add_extension(_key_usage(is_ca=True), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            )

            if intermediate_of:
                issuer_key = self._load_ca_key(intermediate_of, state)
                issuer_cert = self._load_ca_cert(intermediate_of, state)
                builder = builder.issuer_name(issuer_cert.subject).add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
                )
                cert = builder.sign(issuer_key, _digest_algorithm(self.config.digest))
            else:
                builder = builder.issuer_name(_build_name(subject))
                cert = builder.sign(key, _digest_algorithm(self.config.digest))

            key_path = ca_dir / "ca.key.pem"
            cert_path = ca_dir / "ca.cert.pem"
            self._write_private_key(key_path, key)
            self._write_cert(cert_path, cert)

            entry = {
                "kind": "ca",
                "type": "intermediate" if intermediate_of else "root",
                "parent": intermediate_of,
                "subject": subject,
                "key_size": key_size,
                "digest": self.config.digest,
                "days": days,
                "key_available": True,
                "revoked": False,
                "next_serial": 1,
                "created": _now().isoformat(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "key_file": str(key_path.relative_to(self.root)),
                "cert_file": str(cert_path.relative_to(self.root)),
                "chain_file": str((ca_dir / "chain.pem").relative_to(self.root)),
            }
            state["cas"][name] = entry
            self._write_chain(state, ca_dir, intermediate_of)
            return dict(entry, name=name)

    def import_ca(self, name: str, cert_pem: bytes, key_pem: Optional[bytes] = None) -> dict:
        _validate_name(name)
        cert = x509.load_pem_x509_certificate(cert_pem)
        with self._transaction() as state:
            if name in state["cas"]:
                raise ValidationError(f"CA '{name}' already exists")
            ca_dir = self.root / "ca" / name
            ca_dir.mkdir(parents=True, exist_ok=True)
            cert_path = ca_dir / "ca.cert.pem"
            cert_path.write_bytes(cert_pem)

            key_path = None
            key_available = False
            if key_pem:
                key = serialization.load_pem_private_key(key_pem, password=None)
                key_path = ca_dir / "ca.key.pem"
                self._write_private_key(key_path, key)
                key_available = True

            entry = {
                "kind": "ca",
                "type": "imported",
                "parent": None,
                "subject": {"common_name": cert.subject.rfc4514_string()},
                "key_available": key_available,
                "digest": self.config.digest,
                "revoked": False,
                "next_serial": 1,
                "created": _now().isoformat(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "key_file": str(key_path.relative_to(self.root)) if key_path else None,
                "cert_file": str(cert_path.relative_to(self.root)),
                "chain_file": str(cert_path.relative_to(self.root)),
            }
            state["cas"][name] = entry
            return dict(entry, name=name)

    def renew_ca(self, name: str, *, cascade: bool = True) -> dict:
        """Regenerate a CA's key+cert in place and, by default, reissue every
        certificate (leaf or child intermediate) chained through it."""
        with self._transaction() as state:
            entry = state["cas"].get(name)
            if not entry:
                raise NotFoundError(f"CA '{name}' not found")
            if not entry.get("key_available"):
                raise ValidationError("Cannot renew an imported CA without its private key")

            key_size = entry.get("key_size", self.config.key_size)
            days = entry.get("days") or (
                self.config.intermediate_valid_days if entry.get("parent") else self.config.ca_valid_days
            )
            cert = self._issue_ca_cert(state, name, entry, key_size, days)
            entry.update(
                {
                    "next_serial": 1,
                    "revoked": False,
                    "created": _now().isoformat(),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                }
            )

            affected: list[str] = []
            if cascade:
                affected = self._cascade_reissue(state, name)
            return {"ca": dict(entry, name=name), "reissued": affected}

    def _issue_ca_cert(self, state: dict, name: str, entry: dict, key_size: int, days: int) -> x509.Certificate:
        """(Re)generate the key+cert files for CA `name` and return the new cert."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        ca_dir = self.root / "ca" / name
        parent = entry.get("parent")
        if parent:
            _check_not_after_within_issuer(_now() + datetime.timedelta(days=days), state["cas"][parent], parent)

        builder = (
            x509.CertificateBuilder()
            .subject_name(_build_name(entry["subject"]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now())
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0 if parent else None), critical=True)
            .add_extension(_key_usage(is_ca=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )
        if parent:
            issuer_key = self._load_ca_key(parent, state)
            issuer_cert = self._load_ca_cert(parent, state)
            builder = builder.issuer_name(issuer_cert.subject).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
            )
            cert = builder.sign(issuer_key, _digest_algorithm(self.config.digest))
        else:
            builder = builder.issuer_name(_build_name(entry["subject"]))
            cert = builder.sign(key, _digest_algorithm(self.config.digest))

        self._write_private_key(ca_dir / "ca.key.pem", key)
        self._write_cert(ca_dir / "ca.cert.pem", cert)
        self._write_chain(state, ca_dir, parent)
        return cert

    def _cascade_reissue(self, state: dict, ca_name: str) -> list[str]:
        """Reissue every leaf cert and child intermediate CA chained through ca_name."""
        reissued: list[str] = []
        for cert_name, cert_entry in state["certs"].items():
            if cert_entry["issuer"] == ca_name:
                self._rewrite_leaf(state, cert_name, cert_entry)
                reissued.append(cert_name)

        for child_name, child_entry in state["cas"].items():
            if child_entry.get("parent") == ca_name and child_entry.get("key_available"):
                key_size = child_entry.get("key_size", self.config.key_size)
                days = child_entry.get("days", self.config.intermediate_valid_days)
                cert = self._issue_ca_cert(state, child_name, child_entry, key_size, days)
                child_entry.update(
                    {
                        "next_serial": 1,
                        "revoked": False,
                        "created": _now().isoformat(),
                        "not_before": cert.not_valid_before_utc.isoformat(),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                    }
                )
                reissued.append(child_name)
                reissued.extend(self._cascade_reissue(state, child_name))
        return reissued

    # ---- leaf (server/client) certificate lifecycle -------------------------
    def issue_cert(
        self,
        kind: str,
        ca_name: str,
        name: str,
        common_name: str,
        *,
        sans: Optional[list[str]] = None,
        days: Optional[int] = None,
        key_size: Optional[int] = None,
        subject: Optional[dict] = None,
        key_password: Optional[str] = None,
    ) -> dict:
        if kind not in ("server", "client"):
            raise ValidationError("kind must be 'server' or 'client'")
        _validate_name(name)
        key_size = key_size or self.config.key_size
        subject = {**self._default_subject(), **(subject or {}), "common_name": common_name}
        days = days or (self.config.server_valid_days if kind == "server" else self.config.client_valid_days)

        with self._transaction() as state:
            if name in state["certs"]:
                raise ValidationError(f"Certificate '{name}' already exists")
            if ca_name not in state["cas"]:
                raise NotFoundError(f"CA '{ca_name}' not found")

            entry = {
                "kind": kind,
                "issuer": ca_name,
                "subject": subject,
                "sans": sans or [],
                "key_size": key_size,
                "days": days,
                "revoked": False,
            }
            state["certs"][name] = entry
            self._rewrite_leaf(state, name, entry, key_password=key_password)
            return dict(entry, name=name)

    def _rewrite_leaf(self, state: dict, name: str, entry: dict, *, key_password: Optional[str] = None) -> None:
        """Generate a fresh key+cert for a leaf entry and persist to disk,
        updating `entry` in place (used both for first issuance and reissue).
        `key_password`, if given, encrypts the private key at rest (e.g. to
        match FreeRADIUS's eap.conf private_key_password) - it is never
        itself persisted anywhere."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=entry.get("key_size", self.config.key_size))
        cert = self._sign_leaf(
            state, entry["issuer"], key.public_key(), entry["subject"], entry["kind"],
            entry.get("days", self.config.server_valid_days), entry.get("sans"),
        )
        cert_dir = self.root / "certs" / name
        cert_dir.mkdir(parents=True, exist_ok=True)
        key_path = cert_dir / f"{name}.key.pem"
        cert_path = cert_dir / f"{name}.cert.pem"
        self._write_private_key(key_path, key, key_password)
        self._write_cert(cert_path, cert)
        entry.update(
            {
                "revoked": False,
                "created": _now().isoformat(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "key_file": str(key_path.relative_to(self.root)),
                "cert_file": str(cert_path.relative_to(self.root)),
                "serial": cert.serial_number,
                "key_encrypted": bool(key_password),
            }
        )

    def _sign_leaf(self, state, ca_name, public_key, subject, kind, days, sans):
        ca_entry = state["cas"][ca_name]
        _check_not_after_within_issuer(_now() + datetime.timedelta(days=days), ca_entry, ca_name)
        issuer_key = self._load_ca_key(ca_name, state)
        issuer_cert = self._load_ca_cert(ca_name, state)
        serial = ca_entry.get("next_serial", 1)
        ca_entry["next_serial"] = serial + 1

        builder = (
            x509.CertificateBuilder()
            .subject_name(_build_name(subject))
            .issuer_name(issuer_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(_now())
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(is_ca=False), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH if kind == "server" else ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
            )
        )
        if sans:
            entries = []
            for value in sans:
                try:
                    entries.append(x509.IPAddress(ipaddress.ip_address(value)))
                except ValueError:
                    entries.append(x509.DNSName(value))
            builder = builder.add_extension(x509.SubjectAlternativeName(entries), critical=False)

        digest = ca_entry.get("digest", self.config.digest)
        return builder.sign(issuer_key, _digest_algorithm(digest))

    def reissue_cert(self, name: str, *, key_password: Optional[str] = None) -> dict:
        """Regenerate a leaf certificate (new key + cert) reusing its stored
        subject/SANs, signed by the current state of its issuing CA. Pass
        `key_password` to (re-)encrypt the new private key; omit it to leave
        the new key unencrypted, even if the previous one had a password
        (the old password is never stored, so it can't be reused automatically)."""
        with self._transaction() as state:
            entry = state["certs"].get(name)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
            self._rewrite_leaf(state, name, entry, key_password=key_password)
            return dict(entry, name=name)

    def revoke_cert(self, name: str) -> None:
        with self._transaction() as state:
            entry = state["certs"].get(name)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
            entry["revoked"] = True
            entry["revoked_at"] = _now().isoformat()

    def revoke_ca(self, name: str) -> None:
        with self._transaction() as state:
            entry = state["cas"].get(name)
            if not entry:
                raise NotFoundError(f"CA '{name}' not found")
            entry["revoked"] = True
            entry["revoked_at"] = _now().isoformat()

    def delete_cert(self, name: str) -> None:
        with self._transaction() as state:
            entry = state["certs"].pop(name, None)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
        shutil.rmtree(self.root / "certs" / name, ignore_errors=True)

    def generate_crl(self, ca_name: str) -> bytes:
        with self._transaction() as state:
            if ca_name not in state["cas"]:
                raise NotFoundError(f"CA '{ca_name}' not found")
            issuer_key = self._load_ca_key(ca_name, state)
            issuer_cert = self._load_ca_cert(ca_name, state)
            builder = x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject)
            builder = builder.last_update(_now()).next_update(_now() + datetime.timedelta(days=7))
            for cert_entry in state["certs"].values():
                if cert_entry.get("revoked") and cert_entry.get("issuer") == ca_name and "serial" in cert_entry:
                    revoked = (
                        x509.RevokedCertificateBuilder()
                        .serial_number(cert_entry["serial"])
                        .revocation_date(_now())
                        .build()
                    )
                    builder = builder.add_revoked_certificate(revoked)
            digest = state["cas"][ca_name].get("digest", self.config.digest)
            crl = builder.sign(private_key=issuer_key, algorithm=_digest_algorithm(digest))
            crl_bytes = crl.public_bytes(serialization.Encoding.PEM)
            (self.root / "ca" / ca_name / "crl.pem").write_bytes(crl_bytes)
            return crl_bytes

    # ---- listing / expiry status --------------------------------------------
    def list_cas(self) -> list[dict]:
        with self._transaction() as state:
            return [dict(v, name=k) for k, v in state["cas"].items()]

    def list_certs(self) -> list[dict]:
        with self._transaction() as state:
            return [dict(v, name=k) for k, v in state["certs"].items()]

    def get_ca(self, name: str) -> dict:
        with self._transaction() as state:
            entry = state["cas"].get(name)
            if not entry:
                raise NotFoundError(f"CA '{name}' not found")
            return dict(entry, name=name)

    def get_cert(self, name: str) -> dict:
        with self._transaction() as state:
            entry = state["certs"].get(name)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
            return dict(entry, name=name)

    def status_for(self, not_after_iso: str) -> dict:
        not_after = datetime.datetime.fromisoformat(not_after_iso)
        days_left = (not_after - _now()).days
        if days_left < 0:
            level = "expired"
        elif days_left <= self.config.expiry_critical_days:
            level = "critical"
        elif days_left <= self.config.expiry_warning_days:
            level = "warning"
        else:
            level = "ok"
        return {"days_left": days_left, "level": level}

    def dashboard(self) -> dict:
        """Summarize every entity's expiry status, for the UI/CLI overview."""
        cas = [{**entry, **self.status_for(entry["not_after"])} for entry in self.list_cas()]
        certs = [{**entry, **self.status_for(entry["not_after"])} for entry in self.list_certs()]
        levels = [c["level"] for c in cas + certs]
        worst = next((lvl for lvl in ("expired", "critical", "warning") if lvl in levels), "ok")
        return {"cas": cas, "certs": certs, "worst_level": worst}

    # ---- export --------------------------------------------------------------
    def read_file(self, relative_path: str) -> bytes:
        return (self.root / relative_path).read_bytes()

    def export_pkcs12(self, name: str, password: Optional[str] = None, *, key_password: Optional[str] = None) -> bytes:
        with self._transaction() as state:
            entry = state["certs"].get(name)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
            if entry.get("key_encrypted") and not key_password:
                raise ValidationError(
                    f"'{name}'s private key is password-protected; pass key_password to decrypt it for export"
                )
            key = serialization.load_pem_private_key(
                (self.root / entry["key_file"]).read_bytes(),
                password=key_password.encode() if key_password else None,
            )
            cert = x509.load_pem_x509_certificate((self.root / entry["cert_file"]).read_bytes())
            ca_entry = state["cas"][entry["issuer"]]
            chain_data = (self.root / ca_entry["chain_file"]).read_bytes()
            ca_certs = x509.load_pem_x509_certificates(chain_data)

        encryption = (
            serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        )
        return pkcs12.serialize_key_and_certificates(name.encode(), key, cert, ca_certs, encryption)

    def export_pem_bundle(self, name: str) -> dict:
        """Return the raw cert/key/CA-chain PEMs for a certificate, e.g. to
        write out as FreeRADIUS's eap.conf certificate_file/private_key_file/
        ca_file (server certs) or to hand a client its identity + trust chain."""
        with self._transaction() as state:
            entry = state["certs"].get(name)
            if not entry:
                raise NotFoundError(f"Certificate '{name}' not found")
            cert_pem = (self.root / entry["cert_file"]).read_bytes()
            key_pem = (self.root / entry["key_file"]).read_bytes()
            ca_entry = state["cas"][entry["issuer"]]
            chain_pem = (self.root / ca_entry["chain_file"]).read_bytes()
        return {"cert_pem": cert_pem, "key_pem": key_pem, "chain_pem": chain_pem}
