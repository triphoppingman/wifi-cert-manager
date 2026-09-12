# wifi-cert-manager

CA / server / client certificate lifecycle management for WiFi 802.1X
(EAP-TLS) authentication, deployed in front of a FreeRADIUS server.

All logic (CA creation/import, server & client cert issuance, renewal,
cascading reissue, expiry status, PKCS#12/PEM export, key-password handling)
lives in the single library module
[`wifi_cert_manager/core.py`](wifi_cert_manager/core.py). The CLI and the
web UI are both thin wrappers around it, so anything you can do in one you
can do in the other.

State is flat files only - no database:

```
data/
  state.json          # JSON metadata index
  ca/<name>/           # ca.key.pem, ca.cert.pem, chain.pem, crl.pem
  certs/<name>/        # <name>.key.pem, <name>.cert.pem
```

## Running locally

```sh
pip install -r requirements.txt -e .
cp config.example.yaml config.yaml   # optional, defaults work out of the box

# CLI
certmgr ca create root-ca --cn "Example WiFi Root CA"
certmgr server create radius1 --ca root-ca --cn radius.example.com --san radius.example.com
certmgr client create alice --ca root-ca --cn alice@example.com
certmgr status

# Web UI (http://localhost:8080)
python -m wifi_cert_manager.webapp.app
```

Every `certmgr` subcommand reads defaults from `config.yaml` (see
`config.example.yaml` for the full list: key size, digest, validity periods,
default subject fields, expiry thresholds). Any of them can be overridden
per-invocation on the top-level command, e.g.
`certmgr --data-dir /other/path --ca-days 1825 ca create ...`.

## Docker

```sh
docker compose up -d --build
docker compose exec web certmgr status
```

The container entrypoint fixes ownership of the bind-mounted `/data` volume
at startup, then drops from root to an unprivileged user, so any host UID
can own the volume. Override the default `gunicorn` `CMD` to run one-off CLI
commands, e.g. `docker run --rm -v $(pwd)/data:/data <image> certmgr status`.

## Web UI

- **Dashboard**: expiry overview for every CA and cert, colour-coded
  ok/warning/critical/expired.
- **Certificate Authorities**: create a root or intermediate CA, import an
  existing one, renew (with cascading reissue), download the chain, revoke.
- **Server Certs** / **Client Certs**: issue new certs (Common Name
  auto-fills from Name as you type, until you edit it yourself), click any
  row to see its full details below the table, reissue, export as `.p12`,
  export a plain PEM bundle, revoke, delete.
- **Readme**: renders this file in the app so the docs travel with the tool.

Private key passwords (see below) are optional two-field prompts in the
Server/Client creation forms - submission is blocked client- and
server-side if the confirmation doesn't match.

## Certificate model

- **CA**: root or intermediate (`ca create --intermediate-of <parent>`), or
  import an existing one (`ca import --cert ... [--key ...]`). An imported
  CA without a key can issue nothing and cannot be renewed, but downstream
  certs can still be tracked/exported against it.
- **Server / client certs**: each is signed directly by a named CA, with the
  correct `KeyUsage`/`ExtendedKeyUsage` (`serverAuth` vs `clientAuth`) and,
  for servers, `subjectAltName` entries (`--san`, repeatable).
- **Lifetime guardrail**: a cert/intermediate can never be issued or renewed
  with a `not_after` date past its issuing CA's own `not_after` - creation
  fails with a clear error telling you to shorten `--days` or renew the CA
  first, rather than silently minting a cert that outlives its trust anchor.
- **Renew CA (`ca renew`)**: regenerates the CA's key+cert in place and, by
  default (`--cascade`), reissues every cert - and any child intermediate -
  chained through it, so a CA rotation doesn't silently break every
  downstream cert. Cascaded reissues always get an unencrypted key (see
  below), since the previous key's password is never stored.
- **Expiry**: `certmgr status` / the dashboard tab colour-code every CA and
  cert as `ok` / `warning` / `critical` / `expired` based on
  `expiry_warning_days` / `expiry_critical_days` in config.

## Private key passwords

Server/client private keys can optionally be encrypted at rest with a
password (e.g. to match FreeRADIUS's `private_key_password` setting). It's
never persisted anywhere in `state.json` - only whether a key is currently
encrypted (`key_encrypted: true/false`) is recorded.

CLI (double-entry, confirmed for you, mismatches abort):
```sh
certmgr server create radius1 --ca root-ca --cn radius.example.com --ask-key-password
# or, for scripting, pass it directly (no confirmation needed since you typed it once):
certmgr server create radius1 --ca root-ca --cn radius.example.com --key-password 's3cret'
```

Web UI: the Server/Client creation forms have "Private key password" and
"Confirm key password" fields (both optional; leave both blank for no
password). Reissue prompts for a new password via the browser; exporting a
`.p12` for an encrypted cert prompts for the existing password to decrypt it
first.

`certmgr cert export <name> --key-password <existing password>` is required
if the stored key is encrypted - the command fails with a clear error
otherwise.

## FreeRADIUS integration

### 1. Create the CA and server cert

```sh
certmgr ca create wlan-ca --cn "Example WiFi Root CA"
certmgr server create radius1 --ca wlan-ca --cn radius.example.com \
  --san radius.example.com --san 10.0.0.5
```

`--san` accepts DNS names or IP addresses and is repeatable - include every
hostname/IP your APs/controllers will use to reach the RADIUS server, since
strict EAP-TLS clients may check it.

### 2. Export the PEM bundle for `eap.conf`

FreeRADIUS's `mods-available/eap` `tls-config` block wants plain PEM files,
not PKCS#12:

```sh
mkdir -p /etc/raddb/certs/wifi-cert-manager
certmgr cert bundle radius1 --out-dir /etc/raddb/certs/wifi-cert-manager
```

This writes `radius1.crt`, `radius1.key` (mode `0600`, encrypted if you set
a key password) and `ca.pem` (the full chain up to the root). The same
`/api/certs/<name>/bundle` endpoint (a "PEM bundle" button in the web UI)
returns a zip with the same three files - handy if FreeRADIUS runs on a
different host than wifi-cert-manager.

If you generate a Diffie-Hellman params file (FreeRADIUS's default
`eap.conf` still references one for old-style EAP-FAST/TLS setups), keep
using `openssl dhparam -out dh 2048`; wifi-cert-manager doesn't manage it
since it isn't tied to any cert's lifecycle.

### 3. Point `eap.conf` at the exported files

Edit `mods-available/eap` (or `mods-enabled/eap` if not managed via
symlinks), inside the `tls-config tls-common` block used by your
`eap-tls`/`peap`/`ttls` sections:

```
tls-config tls-common {
    private_key_file      = /etc/raddb/certs/wifi-cert-manager/radius1.key
    private_key_password  = "s3cret"   # only if the key was created with one
    certificate_file      = /etc/raddb/certs/wifi-cert-manager/radius1.crt
    ca_file                = /etc/raddb/certs/wifi-cert-manager/ca.pem
    dh_file                = ${certdir}/dh

    # Require the client to present a cert signed by ca_file, i.e. one this
    # tool issued via `certmgr client create`:
    ca_path                = ${certdir}
    check_crl              = yes   # see the CRL section below
    cipher_list             = "HIGH"
    tls_min_version         = "1.2"

    cache {
        enable = yes
        lifetime = 24 # hours
    }
}
```

`eap-tls`/`peap`/`ttls` sections then just reference `tls = tls-common`.
Verify the config parses before restarting:

```sh
radiusd -XC   # or freeradius -XC, depending on distro packaging
```

### 4. Permissions and restart

```sh
chown -R freerad:freerad /etc/raddb/certs/wifi-cert-manager
chmod 750 /etc/raddb/certs/wifi-cert-manager
chmod 640 /etc/raddb/certs/wifi-cert-manager/radius1.key
systemctl restart freeradius
```

FreeRADIUS doesn't hot-reload TLS material - a full restart is required
after any `cert bundle` re-export (new server cert, `ca renew`, or manual
`cert reissue radius1`), not just a config reload.

### 5. Issue and deploy client certs

```sh
certmgr client create alice --ca wlan-ca --cn alice@example.com
certmgr cert export alice --out alice.p12 --password <choose-one>
```

Client certs are installed on the supplicant device (phone/laptop) as a
password-protected PKCS#12 bundle containing the cert, key and CA chain in
one file - most OS wifi cert managers (Android, iOS, Windows, macOS) import
`.p12`/`.pfx` directly. No FreeRADIUS-side config change is needed per
client: any cert chaining to `ca_file` is trusted automatically. If you
want to restrict access further, pair this with `clients.conf` and/or an
`authorize` policy that checks `TLS-Client-Cert-Common-Name` /
`TLS-Client-Cert-Subject` against your user database.

### 6. Configure `clients.conf` for the access points/controllers

Separately from the EAP-TLS server cert, each AP/WLC that talks to
FreeRADIUS needs a RADIUS shared secret entry in `clients.conf` - this is
unrelated to the TLS certs above and not something wifi-cert-manager
manages:

```
client ap-floor1 {
    ipaddr = 10.0.1.10
    secret = <radius shared secret>
}
```

### 7. Test end-to-end

```sh
# Local EAP-TLS handshake test against the running server, using the
# exported client bundle:
eapol_test -c wpa_supplicant.conf -a 127.0.0.1 -s <radius-shared-secret>
```
where `wpa_supplicant.conf` references `alice.p12` (or the unpacked
`.crt`/`.key`/CA chain) as the EAP-TLS client credential. A quick
`radiusd -X` in the foreground is the fastest way to see handshake errors
(cert chain mismatches, expired certs, wrong `private_key_password`, etc.)
before wiring up real access points.

### 8. After a CA renewal

`ca renew` (with the default `--cascade`) reissues the server cert and
every client cert in place. You must:
1. Re-run `cert bundle radius1 --out-dir ...` and restart FreeRADIUS.
2. Re-export and reinstall every client's `.p12` - the old ones no longer
   chain to the new CA/server cert.
3. If any of those certs previously had a key password, re-apply it (see
   [Private key passwords](#private-key-passwords)) since cascaded reissues
   always come back unencrypted.

## Revocation / CRL


`cert revoke <name>` / `ca revoke <name>` just flags an entry as revoked in
`state.json`. Run `ca crl <ca-name> --out ca.crl.pem` to (re)generate the
CRL covering that CA's revoked certs, and point FreeRADIUS's `ca_file`
config (or a separate CRL check) at it.

## Installing client certs on devices

Once you've exported a client bundle:

```sh
certmgr cert export alice --out alice.p12 --password <choose-one>
```

here's how to get it (and the CA's trust anchor) onto each platform's WiFi
802.1X (EAP-TLS) supplicant.

### Windows

1. Copy `alice.p12` to the device.
2. Double-click it (or `certutil -importPFX`) to launch the Certificate
   Import Wizard - choose **Current User** (or **Local Machine** for a
   shared/kiosk device), enter the PKCS#12 password, and let Windows
   auto-select the certificate store (it will file the cert under
   *Personal* and the CA under *Trusted Root Certification Authorities*
   since the bundle includes the chain).
3. In **Settings → Network & Internet → Wi-Fi → Manage known networks →
   Add a new network**, select security type **WPA2/WPA3-Enterprise**, EAP
   method **EAP-TLS**, and pick `alice@example.com` (the cert's Common
   Name) as the client certificate.
4. For unattended rollout, use `certutil -importPFX -p <password> alice.p12`
   plus a WLAN profile XML (`netsh wlan add profile`) referencing the same
   cert by thumbprint - suitable for Group Policy / Intune deployment.

### Android

1. Copy `alice.p12` to the device (or host it somewhere the device can
   download it from over a trusted channel).
2. Open it from Files/Downloads; Android prompts to install a "user
   certificate", asks for the PKCS#12 password, then a device
   PIN/pattern/password (or biometric) to protect the credential storage.
3. In **Settings → Network & Internet → Wi-Fi → (network) → Advanced
   options**, set EAP method **TLS**, and select the imported "CA
   certificate" and "User certificate" (Android splits the bundle back out
   into its component parts automatically).
4. **Set the "Domain" field to the server cert's Common Name/SAN** (e.g.
   `radius.example.com`, whatever you passed to `server create --cn`/`--san`
   when creating `radius1`). Android validates the RADIUS server's cert
   against this domain during the handshake - leaving it blank or
   mismatched is one of the most common reasons EAP-TLS silently fails to
   connect on Android, since the error Android shows ("Couldn't connect")
   gives no indication it was a domain check failure.
5. For MDM-managed fleets (Android Enterprise), push the same `.p12` plus a
   WiFi EAP-TLS configuration profile (including the matching domain) via
   your MDM's Wi-Fi payload instead of manual install.

### Linux

Most Linux desktops use `wpa_supplicant` under the hood (directly, or via
NetworkManager). You can either import the `.p12` as-is, or unpack it first
with the CLI's plain PEM bundle:

```sh
certmgr cert bundle alice --out-dir /etc/wpa_supplicant/certs/alice
```
which gives you `alice.crt`, `alice.key` and `ca.pem` directly.

**NetworkManager (GUI or `nmcli`)**:
```sh
nmcli connection add type wifi con-name wlan-alice ifname wlan0 ssid <SSID> \
  wifi-sec.key-mgmt wpa-eap 802-1x.eap tls \
  802-1x.identity "alice@example.com" \
  802-1x.ca-cert /etc/wpa_supplicant/certs/alice/ca.pem \
  802-1x.client-cert /etc/wpa_supplicant/certs/alice/alice.crt \
  802-1x.private-key /etc/wpa_supplicant/certs/alice/alice.key \
  802-1x.private-key-password '<key password, if any>'
```
(Or Settings → Wi-Fi → the network → Security: WPA & WPA3 Enterprise → EAP
method: TLS, and browse to the same three files.)

**Raw `wpa_supplicant.conf`** (headless devices, IoT, embedded Linux):
```
network={
    ssid="<SSID>"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="alice@example.com"
    ca_cert="/etc/wpa_supplicant/certs/alice/ca.pem"
    client_cert="/etc/wpa_supplicant/certs/alice/alice.crt"
    private_key="/etc/wpa_supplicant/certs/alice/alice.key"
    private_key_passwd="<key password, if any>"
}
```

### After a client cert is reissued or revoked

Any `cert reissue alice` (manual, or automatic via a cascading `ca renew`)
invalidates whatever was previously installed on the device - re-export and
reinstall the new `.p12`/PEM files following the same steps above. A
revoked cert (`cert revoke alice`) should also be removed from the device,
though FreeRADIUS's CRL check (`## Revocation / CRL` above) is what
actually blocks it from authenticating in the meantime.

## Troubleshooting

### FreeRADIUS: "Permission denied" reading cert files

```
tls: (TLS) Failed reading certificate file "/etc/freeradius/3.0/certs/wlan_server.crt"
tls: (TLS) error:8000000D:system library::Permission denied
rlm_eap_tls: Failed initializing SSL context
```

`certmgr cert bundle` writes files owned by whoever ran the command
(mode `0600` for the key), which is almost never the account FreeRADIUS
actually runs as. `freeradius -XC`/`radiusd -XC` run as your login user by
default, which is why the config check may pass while the real service
(running as an unprivileged system account) still fails - or vice versa.

1. **Find the FreeRADIUS process user.** Debian/Ubuntu packages typically
   run it as `freerad`, RHEL/CentOS as `radiusd`. Confirm with:
   ```sh
   systemctl show -p User -p Group freeradius   # or: systemctl cat freeradius
   ```
2. **Re-own and re-permission the exported bundle** for that user (adjust
   the path/user to match step 1):
   ```sh
   chown -R freerad:freerad /etc/freeradius/3.0/certs/wifi-cert-manager
   chmod 750 /etc/freeradius/3.0/certs/wifi-cert-manager
   chmod 640 /etc/freeradius/3.0/certs/wifi-cert-manager/*.crt \
             /etc/freeradius/3.0/certs/wifi-cert-manager/*.pem
   chmod 640 /etc/freeradius/3.0/certs/wifi-cert-manager/*.key
   ```
3. **Check every parent directory is traversable** by that user/group too
   (`chmod 750`/`755` up the tree as needed) - owning the file correctly but
   leaving a `700` parent directory owned by someone else produces the
   exact same "Permission denied" error and is easy to miss.
4. **Check for a mandatory access control profile** (AppArmor on
   Debian/Ubuntu, SELinux on RHEL/Fedora) blocking access even when Unix
   permissions look correct:
   ```sh
   # AppArmor
   aa-status | grep -i freeradius
   dmesg | grep -i apparmor | grep -i freeradius
   # SELinux
   journalctl -k | grep -i avc | grep -i radius
   ```
   If you find denials, either relabel/restore the SELinux context
   (`restorecon -Rv /etc/freeradius/3.0/certs`) or add an AppArmor
   exception for the new cert directory rather than disabling the profile
   entirely.
5. Re-run `freeradius -XC` (or `radiusd -XC`) after each change until it
   passes, then restart the service.

### FreeRADIUS: other common EAP-TLS errors

- **`error:0906D06C:PEM routines:PEM_read_bio:no start line`** - usually
  means `private_key_file`/`certificate_file` in `eap.conf` points at the
  wrong file (e.g. swapped `.crt`/`.key`), or the file was truncated during
  copy.
- **`Failed to decrypt private key` / bad password** - `private_key_password`
  in `eap.conf` doesn't match the password the cert was created with; see
  [Private key passwords](#private-key-passwords). Re-run `cert reissue`
  with `--ask-key-password` if you've lost track of it, then re-export.
- **Handshake succeeds locally but not from real APs/controllers** - check
  that every hostname/IP the AP uses to reach the RADIUS server was
  included as a `--san` on the server cert (some supplicants validate the
  server cert against the configured domain - see the Android note above).
- Config changes never take effect - remember TLS material is only read at
  startup; `systemctl restart freeradius` is required, a reload is not
  enough after rotating certs.

### Client install troubleshooting

- **Windows**: if the cert doesn't appear in the EAP-TLS certificate
  picker, confirm it was imported into the same store the WiFi profile
  expects (**Current User** vs **Local Machine** - a profile created via
  `netsh`/Group Policy for "all users" needs the cert in the Local Machine
  store, e.g. `certutil -importPFX -p <password> -f alice.p12` run
  elevated).
- **Android**: "Couldn't connect" with no further detail almost always
  means either the Domain field doesn't match the server cert (see above)
  or the CA cert wasn't trusted - re-check both before assuming the network
  itself is at fault. Recent Android versions also require the CA cert to
  be installed as a "CA certificate" (not just bundled in the `.p12`) on
  some OEM skins; if in doubt import `ca.pem` separately as well via
  **Settings → Security → Encryption & credentials → Install a certificate
  → CA certificate**.
- **Linux**: run `wpa_supplicant` in the foreground with verbose logging to
  see the actual TLS alert instead of guessing:
  ```sh
  wpa_supplicant -dd -c wpa_supplicant.conf -i wlan0
  ```
  or, for NetworkManager-managed connections, `journalctl -u
  NetworkManager -f` while reconnecting. A private key with the wrong file
  permissions (e.g. `0600` owned by root when NetworkManager runs as your
  user) will fail silently in the UI but show clearly in these logs.
