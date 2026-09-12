// Vanilla JS SPA-lite front end: talks to /api/* only, so the backend can
// later grow a richer client (React etc.) without changing wifi_cert_manager.core.

const toast = document.getElementById("toast");

function showToast(msg, isError = false) {
  toast.textContent = msg;
  toast.style.display = "block";
  toast.style.background = isError ? "#c62828" : "#1c2733";
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => (toast.style.display = "none"), 4000);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: options.body && !(options.body instanceof FormData) ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(data.error || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res;
}

function badge(level, daysLeft) {
  return `<span class="badge ${level}">${level} (${daysLeft}d)</span>`;
}

function fmtDate(iso) {
  return iso ? iso.split(".")[0].replace("T", " ") : "";
}

// Autofill Common Name from Name as the user types, unless they've
// manually edited Common Name themselves (or after a form reset).
function setupNameAutofill(formId) {
  const form = document.getElementById(formId);
  const nameInput = form.querySelector('[name="name"]');
  const cnInput = form.querySelector('[name="common_name"]');
  let cnEdited = false;

  nameInput.addEventListener("input", () => {
    if (!cnEdited) cnInput.value = nameInput.value;
  });
  cnInput.addEventListener("input", () => {
    cnEdited = true;
  });
  form.addEventListener("reset", () => {
    cnEdited = false;
  });
}

// ---- tabs -------------------------------------------------------------
document.querySelectorAll("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "readme") loadReadme();
  });
});

// ---- readme -------------------------------------------------------------
let readmeLoaded = false;
async function loadReadme() {
  if (readmeLoaded) return;
  const container = document.getElementById("readme-content");
  try {
    const res = await fetch("/api/readme");
    container.innerHTML = await res.text();
    readmeLoaded = true;
  } catch (err) {
    container.textContent = `Failed to load README: ${err.message}`;
  }
}

// ---- dashboard ----------------------------------------------------------
async function loadDashboard() {
  const dash = await api("/api/dashboard");
  document.getElementById("dashboard-summary").innerHTML =
    `Overall status: ${badge(dash.worst_level, "")}`.replace(" (d)", "");

  const caBody = document.querySelector("#dashboard-cas tbody");
  caBody.innerHTML = dash.cas
    .map(
      (c) =>
        `<tr><td>${c.name}</td><td>${c.type}</td><td>${fmtDate(c.not_after)}</td><td>${c.days_left}</td><td>${badge(c.level, c.days_left)}</td></tr>`
    )
    .join("");

  const certBody = document.querySelector("#dashboard-certs tbody");
  certBody.innerHTML = dash.certs
    .map(
      (c) =>
        `<tr><td>${c.name}</td><td>${c.kind}</td><td>${c.issuer}</td><td>${fmtDate(c.not_after)}</td><td>${c.days_left}</td><td>${badge(c.level, c.days_left)}</td></tr>`
    )
    .join("");
}

// ---- CAs ------------------------------------------------------------------
async function loadCAs() {
  const cas = await api("/api/cas");
  const body = document.querySelector("#ca-table tbody");
  body.innerHTML = cas
    .map((c) => {
      const status = c.not_after ? "" : "";
      return `<tr>
        <td>${c.name}</td><td>${c.type}</td><td>${c.parent || "-"}</td><td>${fmtDate(c.not_after)}</td>
        <td>${c.revoked ? '<span class="badge critical">revoked</span>' : ""}</td>
        <td>
          <button data-action="renew" data-name="${c.name}" ${c.key_available ? "" : "disabled"}>Renew</button>
          <button data-action="download" data-name="${c.name}">Download chain</button>
          <button data-action="revoke-ca" data-name="${c.name}" class="danger">Revoke</button>
        </td>
      </tr>`;
    })
    .join("");

  // populate CA selects on server/client forms
  const options = cas.map((c) => `<option value="${c.name}">${c.name}</option>`).join("");
  document.querySelectorAll('select[name="ca_name"]').forEach((sel) => (sel.innerHTML = options));
}

document.querySelector("#ca-table").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const { action, name } = btn.dataset;
  try {
    if (action === "renew") {
      if (!confirm(`Renew CA '${name}'? All certs it issued will be reissued too.`)) return;
      const result = await api(`/api/cas/${name}/renew`, { method: "POST", body: JSON.stringify({ cascade: true }) });
      showToast(`Renewed '${name}'. Reissued: ${result.reissued.join(", ") || "none"}`);
      await Promise.all([loadCAs(), loadDashboard(), loadCerts()]);
    } else if (action === "revoke-ca") {
      if (!confirm(`Revoke CA '${name}'?`)) return;
      await api(`/api/cas/${name}/revoke`, { method: "POST" });
      showToast(`Revoked '${name}'`);
      await loadCAs();
    } else if (action === "download") {
      window.location = `/api/cas/${name}/download`;
    }
  } catch (err) {
    showToast(err.message, true);
  }
});

document.getElementById("form-ca-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const body = {
    name: form.get("name"),
    common_name: form.get("common_name"),
    intermediate_of: form.get("intermediate_of") || null,
    days: form.get("days") ? Number(form.get("days")) : null,
  };
  try {
    await api("/api/cas", { method: "POST", body: JSON.stringify(body) });
    showToast(`Created CA '${body.name}'`);
    e.target.reset();
    await Promise.all([loadCAs(), loadDashboard()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

document.getElementById("form-ca-import").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  try {
    await api("/api/cas/import", { method: "POST", body: form });
    showToast(`Imported CA '${form.get("name")}'`);
    e.target.reset();
    await Promise.all([loadCAs(), loadDashboard()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

// ---- server / client certs ------------------------------------------------
const certsByName = {};
const selectedCert = { server: null, client: null };

function certRow(c) {
  return `<tr class="selectable" data-name="${c.name}">
    <td>${c.name}</td><td>${c.issuer}</td><td>${fmtDate(c.not_after)}</td>
    <td>${badge(c.level, c.days_left)}${c.revoked ? ' <span class="badge critical">revoked</span>' : ""}</td>
    <td>
      <button data-action="reissue" data-name="${c.name}">Reissue</button>
      <button data-action="export" data-name="${c.name}">Export .p12</button>
      <button data-action="bundle" data-name="${c.name}">PEM bundle</button>
      <button data-action="revoke" data-name="${c.name}" class="danger">Revoke</button>
      <button data-action="delete" data-name="${c.name}" class="danger">Delete</button>
    </td>
  </tr>`;
}

function renderCertDetails(kind) {
  const panel = document.getElementById(`${kind}-details`);
  const name = selectedCert[kind];
  const c = name && certsByName[name];
  if (!c) {
    panel.innerHTML = "Select a certificate above to see its details.";
    return;
  }
  const sans = (c.sans || []).join(", ") || "-";
  const subject = c.subject || {};
  panel.innerHTML = `<dl>
    <dt>Name</dt><dd>${c.name}</dd>
    <dt>Kind</dt><dd>${c.kind}</dd>
    <dt>Issuer CA</dt><dd>${c.issuer}</dd>
    <dt>Status</dt><dd>${badge(c.level, c.days_left)}${c.revoked ? ' <span class="badge critical">revoked</span>' : ""}</dd>
    <dt>Common Name</dt><dd>${subject.common_name || "-"}</dd>
    <dt>Subject</dt><dd>C=${subject.country || "-"}, ST=${subject.state_name || "-"}, L=${subject.locality || "-"}, O=${subject.org || "-"}, OU=${subject.org_unit || "-"}, email=${subject.email || "-"}</dd>
    <dt>SANs</dt><dd>${sans}</dd>
    <dt>Key size</dt><dd>${c.key_size} bits</dd>
    <dt>Key password protected</dt><dd>${c.key_encrypted ? "yes" : "no"}</dd>
    <dt>Serial</dt><dd>${c.serial}</dd>
    <dt>Created</dt><dd>${fmtDate(c.created)}</dd>
    <dt>Not Before</dt><dd>${fmtDate(c.not_before)}</dd>
    <dt>Not After</dt><dd>${fmtDate(c.not_after)}</dd>
    <dt>Cert file</dt><dd>${c.cert_file}</dd>
    <dt>Key file</dt><dd>${c.key_file}</dd>
  </dl>`;
}

function selectCertRow(kind, name) {
  selectedCert[kind] = name;
  document.querySelectorAll(`#${kind}-table tbody tr`).forEach((tr) => {
    tr.classList.toggle("selected", tr.dataset.name === name);
  });
  renderCertDetails(kind);
}

async function loadCerts() {
  const dash = await api("/api/dashboard");
  const servers = dash.certs.filter((c) => c.kind === "server");
  const clients = dash.certs.filter((c) => c.kind === "client");
  for (const name of Object.keys(certsByName)) delete certsByName[name];
  dash.certs.forEach((c) => (certsByName[c.name] = c));
  document.querySelector("#server-table tbody").innerHTML = servers.map(certRow).join("");
  document.querySelector("#client-table tbody").innerHTML = clients.map(certRow).join("");

  for (const kind of ["server", "client"]) {
    const stillExists = selectedCert[kind] && certsByName[selectedCert[kind]];
    if (stillExists) {
      selectCertRow(kind, selectedCert[kind]);
    } else {
      selectedCert[kind] = null;
      renderCertDetails(kind);
    }
  }
}

async function handleCertAction(e) {
  const btn = e.target.closest("button");
  if (!btn) {
    const row = e.target.closest("tr[data-name]");
    if (row) {
      const kind = row.closest("table").id === "server-table" ? "server" : "client";
      selectCertRow(kind, row.dataset.name);
    }
    return;
  }
  const { action, name } = btn.dataset;
  try {
    if (action === "reissue") {
      const keyPassword = promptKeyPassword(`Reissuing '${name}'`);
      if (keyPassword === undefined) return; // cancelled or mismatch
      await api(`/api/certs/${name}/reissue`, {
        method: "POST",
        body: JSON.stringify({ key_password: keyPassword, key_password_confirm: keyPassword }),
      });
      showToast(`Reissued '${name}'`);
    } else if (action === "revoke") {
      if (!confirm(`Revoke certificate '${name}'?`)) return;
      await api(`/api/certs/${name}/revoke`, { method: "POST" });
      showToast(`Revoked '${name}'`);
    } else if (action === "delete") {
      if (!confirm(`Delete certificate '${name}' and its key material?`)) return;
      await api(`/api/certs/${name}`, { method: "DELETE" });
      showToast(`Deleted '${name}'`);
    } else if (action === "export") {
      let url = `/api/certs/${name}/export`;
      if (certsByName[name] && certsByName[name].key_encrypted) {
        const pw = window.prompt(`'${name}'s private key is password-protected. Enter its password to export:`);
        if (pw === null) return;
        url += `?key_password=${encodeURIComponent(pw)}`;
      }
      window.location = url;
      return;
    } else if (action === "bundle") {
      window.location = `/api/certs/${name}/bundle`;
      return;
    }
    await Promise.all([loadCerts(), loadDashboard()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

// Prompt twice for an optional password, requiring the two entries to
// match. Returns "" for no password, a string for a confirmed password,
// or undefined if the user cancelled or the entries didn't match.
function promptKeyPassword(context) {
  const first = window.prompt(`${context}: private key password (leave blank for none)`);
  if (first === null) return undefined;
  const second = window.prompt("Repeat private key password to confirm");
  if (second === null) return undefined;
  if (first !== second) {
    showToast("Passwords do not match", true);
    return undefined;
  }
  return first;
}

document.querySelector("#server-table").addEventListener("click", handleCertAction);
document.querySelector("#client-table").addEventListener("click", handleCertAction);

document.getElementById("form-server-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const sans = (form.get("sans") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const keyPassword = form.get("key_password") || "";
  const keyPasswordConfirm = form.get("key_password_confirm") || "";
  if (keyPassword !== keyPasswordConfirm) {
    showToast("Private key password and confirmation do not match", true);
    return;
  }
  const body = {
    kind: "server",
    name: form.get("name"),
    ca_name: form.get("ca_name"),
    common_name: form.get("common_name"),
    sans,
    days: form.get("days") ? Number(form.get("days")) : null,
    key_password: keyPassword,
    key_password_confirm: keyPasswordConfirm,
  };
  try {
    await api("/api/certs", { method: "POST", body: JSON.stringify(body) });
    showToast(`Issued server cert '${body.name}'`);
    e.target.reset();
    await Promise.all([loadCerts(), loadDashboard()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

document.getElementById("form-client-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const keyPassword = form.get("key_password") || "";
  const keyPasswordConfirm = form.get("key_password_confirm") || "";
  if (keyPassword !== keyPasswordConfirm) {
    showToast("Private key password and confirmation do not match", true);
    return;
  }
  const body = {
    kind: "client",
    name: form.get("name"),
    ca_name: form.get("ca_name"),
    common_name: form.get("common_name"),
    days: form.get("days") ? Number(form.get("days")) : null,
    key_password: keyPassword,
    key_password_confirm: keyPasswordConfirm,
  };
  try {
    await api("/api/certs", { method: "POST", body: JSON.stringify(body) });
    showToast(`Issued client cert '${body.name}'`);
    e.target.reset();
    await Promise.all([loadCerts(), loadDashboard()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

// ---- init -------------------------------------------------------------
setupNameAutofill("form-server-create");
setupNameAutofill("form-client-create");

(async function init() {
  try {
    await Promise.all([loadDashboard(), loadCAs(), loadCerts()]);
  } catch (err) {
    showToast(err.message, true);
  }
})();
