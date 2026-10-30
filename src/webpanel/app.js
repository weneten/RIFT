"use strict";

// All values from the server are written with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
const REFRESH_MS = 10000;
let timer = null;
let data = null;
let canWrite = false;

async function api(path, body) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-Rift-Panel"] = "1";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let result = null;
  try { result = await response.json(); } catch (_) { /* empty body */ }
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("session expired");
  }
  if (!response.ok) throw new Error((result && result.error) || response.statusText);
  return result;
}

const act = (body) => api("/api/action", body);

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

const pill = (text, kind) => el("span", { class: `pill ${kind}` }, text);

function ago(unix, now) {
  if (!unix) return "never";
  const s = Math.max(0, now - unix);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function left(unix, now) {
  const s = Math.max(0, unix - now);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.ceil(s / 60)}m`;
  return `${Math.floor(s / 3600)}h ${Math.ceil((s % 3600) / 60)}m`;
}

function range(r) {
  if (!r) return "-";
  return r.start === r.end ? String(r.start) : `${r.start}-${r.end}`;
}

function endpoint(ip, ports) {
  return String(ip).includes(":") ? `[${ip}]:${ports}` : `${ip}:${ports}`;
}

function access(a) {
  if (a === "server") return "host";
  if (a === "full") return "host, all protocols";
  if (a && a.port) return `port ${range(a.port.ports)}/${a.port.protocol}`;
  if (a && a.subnet) return `${a.subnet.net}${a.subnet.snat ? " (SNAT)" : ""}`;
  return JSON.stringify(a);
}

function showBanner(text) {
  const banner = $("banner");
  banner.textContent = text || "";
  banner.hidden = !text;
}

// ---------- dialogs and forms ----------

function closeModal() {
  $("modal").hidden = true;
  $("modal-body").replaceChildren();
}

function openModal(title, ...content) {
  $("modal-title").textContent = title;
  $("modal-body").replaceChildren(...content);
  $("modal").hidden = false;
  const first = $("modal-body").querySelector("input, select, button");
  if (first) first.focus();
}

function row(label, input) {
  const id = `f-${Math.random().toString(36).slice(2)}`;
  input.id = id;
  return el("div", { class: "row" }, el("label", { for: id }, label), input);
}

function check(label, input) {
  return el("label", { class: "check" }, input, label);
}

function select(options, value) {
  const node = el("select", {});
  for (const [v, text] of options) node.append(el("option", { value: v, selected: v === value }, text));
  return node;
}

// A form whose submit runs `submit()`; errors stay in the dialog.
function form(fields, submitLabel, submit) {
  const error = el("p", { class: "error", role: "alert" });
  const button = el("button", { type: "submit", class: "primary" }, submitLabel);
  const node = el("form", { class: "form" }, fields, error,
    el("div", { class: "buttons" }, el("button", { type: "button", onclick: closeModal }, "Cancel"), button));
  node.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    error.textContent = "";
    try {
      await submit();
    } catch (e) {
      error.textContent = e.message;
    } finally {
      button.disabled = false;
    }
  });
  return node;
}

async function copy(text, button) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = el("textarea", { readonly: true, class: "offscreen" });
      area.value = text;
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    button.textContent = "Copied";
  } catch (_) {
    button.textContent = "Select and copy manually";
  }
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = el("a", { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function button(label, onclick, kind) {
  return el("button", { type: "button", class: kind || "", onclick }, label);
}

// Runs a change from a table button and refreshes; errors go to the banner.
function actionButton(label, body, confirmText, kind) {
  return button(label, async (event) => {
    if (confirmText && !window.confirm(confirmText)) return;
    const node = event.currentTarget;
    node.disabled = true;
    try {
      await act(body);
      await load();
    } catch (e) {
      showBanner(`Action failed: ${e.message}`);
      node.disabled = false;
    }
  }, kind);
}

function agentOptions(onlyActive) {
  return (data.agents || [])
    .filter((a) => !onlyActive || a.status === "active")
    .map((a) => [a.name, a.name]);
}

function inviteDialog() {
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "node2" });
  const ttl = select([["15m", "15 minutes"], ["30m", "30 minutes"], ["1h", "1 hour"], ["24h", "24 hours"]], "15m");
  openModal("Invite agent", form([
    row("Agent name", name),
    row("Valid for", ttl),
    el("p", { class: "hint" }, "The enrollment port opens now and closes again when the agent is active, the invitation expires or is cancelled."),
  ], "Create invitation", async () => {
    const result = await act({ action: "agent_invite", name: name.value.trim(), ttl: ttl.value });
    await load();
    const copyButton = button("Copy", (e) => copy(result.lines, e.currentTarget), "primary");
    openModal(`Invitation for ${result.name}`,
      el("p", { class: "hint" }, "Put these three lines into the agent's .env, then start it. The token is a secret and works once."),
      el("pre", { class: "pre" }, result.lines),
      el("div", { class: "form" }, el("div", { class: "buttons" }, copyButton, button("Done", closeModal))));
  }));
}

function forwardDialog() {
  const agents = agentOptions(true);
  if (!agents.length) {
    showBanner("No active agent yet. Invite one first.");
    return;
  }
  const agent = select(agents, agents[0][0]);
  const specs = el("input", { required: true, placeholder: "8080:80/tcp 53/both 5000-5002/udp" });
  const ips = (data.public_ips || []).map((ip) => [ip, ip]);
  const listen = select(ips, ips.length ? ips[0][0] : "");
  const mode = select([["transparent", "transparent (client IP visible)"], ["translate", "translate (IPv4 ↔ IPv6)"]], "transparent");
  const ingress = select([["public", "public"], ["local", "local (for a proxy on this server)"]], "public");
  const family = select([["", "same as listen IP"], ["v4", "IPv4"], ["v6", "IPv6"]], "");
  openModal("Add forwards", form([
    row("Agent", agent),
    row("Ports", specs),
    el("p", { class: "hint" }, "LISTEN[:TARGET]/tcp, /udp or /both, several separated by spaces. The target defaults to the listen port."),
    el("div", { class: "row inline" }, row("Listen IP", listen), row("Mode", mode)),
    el("div", { class: "row inline" }, row("Ingress", ingress), row("Target family", family)),
    el("p", { class: "hint" }, "Open the public ports in your cloud or upstream firewall as well."),
  ], "Add", async () => {
    const body = { action: "forward_add", agent: agent.value, specs: specs.value, mode: mode.value, ingress: ingress.value };
    if (listen.value) body.listen_ip = listen.value;
    if (family.value) body.target_family = family.value;
    await act(body);
    closeModal();
    await load();
  }));
}

function banDialog(forward) {
  const ip = el("input", { required: true, placeholder: "198.51.100.23" });
  const ttl = select([["10m", "10 minutes"], ["1h", "1 hour"], ["6h", "6 hours"], ["24h", "24 hours"]], "1h");
  openModal(`Ban a client on forward ${forward.id}`, form([
    row("Client address", ip),
    row("Duration", ttl),
  ], "Ban", async () => {
    await act({ action: "ban_add", agent: forward.agent, forward_id: forward.id, ip: ip.value.trim(), ttl: ttl.value });
    closeModal();
    await load();
  }));
}

function deviceDialog() {
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "phone" });
  const panel = el("input", { type: "checkbox" });
  openModal("Add VPN device", form([
    row("Device name", name),
    check("May open this panel", panel),
    el("p", { class: "hint" }, "A new device reaches nothing until you grant it access."),
  ], "Create", async () => {
    const created = name.value.trim();
    await act({ action: "vpn_peer_add", name: created, panel: panel.checked });
    await load();
    if (panel.checked) await configDialog(created);
    else grantsDialog(created);
  }));
}

async function configDialog(name) {
  let result;
  try {
    result = await act({ action: "vpn_config", name });
  } catch (e) {
    showBanner(`Configuration of ${name}: ${e.message}`);
    closeModal();
    return;
  }
  const image = el("img", { alt: `WireGuard QR code for ${name}`, src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(result.qr_svg)}` });
  openModal(`WireGuard configuration: ${name}`,
    el("p", { class: "warn-text" }, "Contains the device's private key. Do not share or store it carelessly."),
    el("div", { class: "qr" }, image),
    el("pre", { class: "pre" }, result.config),
    el("div", { class: "form" }, el("div", { class: "buttons" },
      button("Copy", (e) => copy(result.config, e.currentTarget)),
      button("Download .conf", () => download(`${name}.conf`, result.config)),
      button("Done", closeModal, "primary"))));
}

function grantsDialog(name) {
  const peer = (data.vpn_peers || []).find((p) => p.name === name);
  if (!peer) { closeModal(); return; }
  const refresh = async () => { await load(); grantsDialog(name); };
  const list = el("ul", { class: "grant-list" });
  if (peer.panel) {
    list.append(el("li", {}, el("span", {}, "web panel"),
      button("Withdraw", async () => { await act({ action: "panel_allow", name, allowed: false }); await refresh(); }, "danger")));
  }
  for (const g of peer.grants || []) {
    list.append(el("li", {}, el("span", {}, `${g.agent || "?"}: ${access(g.access)}`),
      button("Withdraw", async () => {
        try {
          await act({ action: "vpn_deny", peer: name, agent: g.agent, access: g.access });
          await refresh();
        } catch (e) { showBanner(e.message); }
      }, "danger")));
  }
  if (!list.children.length) list.append(el("li", { class: "muted" }, "No access yet."));

  const agents = agentOptions(true);
  const content = [el("h4", {}, "Current access"), list];
  if (agents.length) {
    const agent = select(agents, agents[0][0]);
    const kind = select([["server", "the agent host (TCP, UDP, ping)"], ["full", "the agent host, all protocols"], ["ports", "ports on the agent host"], ["subnet", "a network behind the agent"]], "server");
    const value = el("input", { placeholder: "" });
    const snat = el("input", { type: "checkbox" });
    const valueRow = row("Ports or network", value);
    const snatRow = check("Masquerade (SNAT) on the agent, if the LAN router has no route back", snat);
    const update = () => {
      valueRow.hidden = kind.value === "server" || kind.value === "full";
      value.required = !valueRow.hidden;
      value.placeholder = kind.value === "ports" ? "22/tcp 53/both" : "192.168.178.0/24";
      snatRow.hidden = kind.value !== "subnet";
    };
    kind.addEventListener("change", update);
    update();
    content.push(el("hr", { class: "sep" }), el("h4", {}, "Allow more"), form([
      el("div", { class: "row inline" }, row("Agent", agent), row("Access to", kind)),
      valueRow, snatRow,
    ], "Allow", async () => {
      const body = { action: "vpn_allow", peer: name, agent: agent.value };
      if (kind.value === "server") body.server = true;
      if (kind.value === "full") body.full = true;
      if (kind.value === "ports") body.ports = value.value;
      if (kind.value === "subnet") { body.subnets = value.value; body.snat = snat.checked; }
      await act(body);
      await refresh();
    }));
  }
  content.push(el("p", { class: "hint" }, "After a change, re-import the device's configuration so it routes the new addresses."),
    el("div", { class: "form" }, el("div", { class: "buttons" },
      button("Show configuration", () => configDialog(name)), button("Done", closeModal, "primary"))));
  openModal(`Access of ${name}`, ...content);
}

// ---------- rendering ----------

function fill(tbody, rows, columns, emptyText) {
  tbody.replaceChildren();
  if (!rows.length) {
    tbody.append(el("tr", {}, el("td", { class: "empty", colspan: columns }, emptyText)));
    return;
  }
  for (const r of rows) tbody.append(r);
}

const writeOnly = (...nodes) => (canWrite ? nodes : []);
const btns = (...nodes) => el("div", { class: "btns" }, ...writeOnly(...nodes));

function setPill(id, text, kind) {
  $(id).replaceWith(Object.assign(pill(text, kind), { id }));
}

function render() {
  const now = data.time;
  const agents = data.agents || [];
  const forwards = data.forwards || [];
  const peers = Array.isArray(data.vpn_peers) ? data.vpn_peers : [];
  const panel = data.panel || {};
  const enrollment = data.enrollment || {};
  const invites = data.invites || [];
  canWrite = !!data.can_write;

  for (const node of document.querySelectorAll(".write")) node.hidden = !canWrite;
  $("readonly").hidden = canWrite;
  setPill("access", canWrite ? "full access" : "read-only", canWrite ? "ok" : "off");
  if (data.apply_error) setPill("state", "error", "bad");
  else if (data.fully_applied) setPill("state", "applied", "ok");
  else setPill("state", "applying", "warn");
  if (data.apply_error) showBanner(`Last apply failed: ${data.apply_error}`);

  const active = agents.filter((a) => a.status === "active");
  $("t-agents").textContent = `${active.filter((a) => a.online).length} / ${active.length}`;
  $("t-forwards").textContent = `${forwards.filter((f) => f.enabled).length} / ${forwards.length}`;
  $("t-vpn").textContent = `${peers.filter((p) => p.enabled).length} / ${peers.length}`;
  const port = String(enrollment.bind || "").split(":").pop();
  $("t-enroll").textContent = enrollment.mode === "off" ? "off" : enrollment.open ? `${port} open` : "closed";
  $("t-enroll-sub").textContent = enrollment.mode === "always" ? "always open"
    : enrollment.mode === "auto" ? (enrollment.open ? "until the invitations are done" : "opens with an invitation")
    : "";

  const inviteList = $("invites");
  inviteList.replaceChildren();
  for (const i of invites) {
    inviteList.append(el("li", {},
      el("span", {}, "Invitation ", el("strong", {}, i.name), el("span", { class: "muted" }, ` · expires in ${left(i.expires_at, now)}`)),
      btns(actionButton("Cancel", { action: "agent_cancel_invite", name: i.name }, `Cancel the invitation for ${i.name}?`))));
  }

  fill($("agents"), agents.map((a) => {
    const connection = a.status === "active"
      ? el("span", {}, el("span", { class: `dot ${a.online ? "ok" : "bad"}` }), a.online ? "online" : "offline")
      : el("span", { class: "muted" }, "-");
    const statePill = a.status === "active"
      ? (a.configuration_ready ? pill("active", "ok") : pill("syncing", "warn"))
      : a.status === "pending" ? pill("enrolling", "warn") : pill("disabled", "off");
    let actions;
    if (a.status === "pending") {
      actions = btns(actionButton("Cancel", { action: "agent_cancel_invite", name: a.name }, `Cancel the enrollment of ${a.name}?`));
    } else {
      actions = btns(
        button("Rename", async () => {
          const next = window.prompt(`New name for ${a.name}`, a.name);
          if (!next || next === a.name) return;
          try { await act({ action: "agent_rename", name: a.id, new_name: next.trim() }); await load(); } catch (e) { showBanner(e.message); }
        }),
        actionButton("Rotate key", { action: "agent_rotate", name: a.id }, `Rotate the WireGuard key of ${a.name}? It happens on the agent's next sync.`),
        a.status === "active"
          ? actionButton("Disable", { action: "agent_enable", name: a.id, enabled: false }, `Disable ${a.name}? Its forwards and VPN access stop until it is enabled again.`)
          : actionButton("Enable", { action: "agent_enable", name: a.id, enabled: true }),
        actionButton("Remove", { action: "agent_remove", name: a.id }, `Remove ${a.name} with all its forwards and VPN grants? This cannot be undone.`, "danger"));
    }
    return el("tr", {},
      el("td", {}, a.name),
      el("td", {}, connection),
      el("td", {}, statePill, a.last_error ? el("span", { class: "muted small", title: a.last_error }, " ⚠") : null),
      el("td", {}, el("code", {}, a.tunnel_ipv4 || "-")),
      el("td", {}, a.status === "active" ? ago(a.last_handshake, now) : "-"),
      el("td", { class: "actions" }, actions));
  }), 6, invites.length ? "No agent has enrolled yet." : "No agents yet.");

  fill($("forwards"), forwards.map((f) => {
    const statePill = !f.enabled ? pill("disabled", "off") : f.pending ? pill("pending", "warn") : pill("active", "ok");
    const mode = [f.mode, f.ingress === "local" ? "local" : null, f.target_family].filter(Boolean).join(" · ");
    return el("tr", {},
      el("td", {}, f.id),
      el("td", {}, f.agent),
      el("td", {}, String(f.protocol || "").toUpperCase()),
      el("td", {}, el("code", {}, endpoint(f.listen_ip, range(f.listen_ports)))),
      el("td", {}, range(f.target_ports)),
      el("td", { class: "muted" }, mode),
      el("td", {}, statePill),
      el("td", { class: "actions" }, btns(
        f.mode === "translate" ? button("Ban", () => banDialog(f)) : null,
        f.enabled
          ? actionButton("Disable", { action: "forward_enable", id: f.id, enabled: false })
          : actionButton("Enable", { action: "forward_enable", id: f.id, enabled: true }),
        actionButton("Remove", { action: "forward_remove", id: f.id },
          `Remove forward ${f.id} (${endpoint(f.listen_ip, range(f.listen_ports))})? This cannot be undone.`, "danger"))));
  }), 8, "No forwards configured.");

  const bans = data.bans || [];
  $("bans-card").hidden = !bans.length;
  fill($("bans"), bans.map((b) => el("tr", {},
    el("td", {}, b.forward_id), el("td", {}, b.agent), el("td", {}, el("code", {}, b.ip)),
    el("td", {}, `in ${left(b.expires_at, now)}`))), 4, "");

  fill($("vpn"), peers.map((p) => {
    const grants = (p.grants || []).map((g) => `${g.agent || "?"}: ${access(g.access)}`);
    if (p.panel) grants.unshift("panel");
    return el("tr", {},
      el("td", {}, p.name),
      el("td", {}, el("code", {}, p.ipv4)),
      el("td", {}, p.enabled ? pill("enabled", "ok") : pill("disabled", "off")),
      el("td", {}, ago(p.last_handshake, now)),
      el("td", { class: "wrap" }, grants.length ? grants.join("; ") : el("span", { class: "muted" }, "none")),
      el("td", { class: "actions" }, btns(
        button("Access", () => grantsDialog(p.name)),
        button("Config", () => configDialog(p.name)),
        p.enabled
          ? actionButton("Disable", { action: "vpn_peer_enable", name: p.name, enabled: false },
            `Disable ${p.name}? If you are connected through this device, you lose the panel.`)
          : actionButton("Enable", { action: "vpn_peer_enable", name: p.name, enabled: true }),
        actionButton("Revoke", { action: "vpn_peer_revoke", name: p.name },
          `Revoke ${p.name}? Its key and all grants are deleted. If you are connected through it, you lose the panel.`, "danger"))));
  }), 6, "No VPN devices registered.");

  const urls = $("panel-urls");
  urls.replaceChildren();
  for (const u of panel.urls || []) {
    urls.append(el("li", {}, el("code", {}, u.url), el("span", { class: "muted" }, u.via)));
  }
  const devices = (panel.devices || []).map((d) => d.name);
  urls.append(el("li", {}, el("span", { class: "muted" }, "Devices with panel access:"), devices.length ? devices.join(", ") : "none"));
  if ((panel.allow || []).length) {
    urls.append(el("li", {}, el("span", { class: "muted" }, "Allowed addresses:"), panel.allow.join(", ")));
  }

  $("updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function load() {
  try {
    data = await api("/api/overview");
    if (!data.apply_error) showBanner("");
    render();
  } catch (e) {
    if (e.message !== "session expired") showBanner(`Could not load: ${e.message}`);
  }
}

async function loadLogs() {
  try {
    const result = await act({ action: "logs", lines: 300 });
    const lines = result.lines || [];
    $("logs").textContent = lines.length ? lines.join("\n") : "No recent log entries.";
  } catch (e) { $("logs").textContent = e.message; }
}

async function loadDiagnostics() {
  try {
    $("diag").textContent = JSON.stringify(await act({ action: "diagnostics" }), null, 2);
  } catch (e) { $("diag").textContent = e.message; }
}

function schedule() {
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
}

function showLogin() {
  clearInterval(timer);
  closeModal();
  $("app").hidden = true;
  $("login").hidden = false;
  $("password").focus();
}

async function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
  await load();
  schedule();
}

document.addEventListener("DOMContentLoaded", async () => {
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter || event.target.querySelector("button");
    submit.disabled = true;
    $("login-error").textContent = "";
    try {
      await api("/api/login", { password: $("password").value });
      $("password").value = "";
      await showApp();
    } catch (e) {
      $("login-error").textContent = e.message === "wrong password" ? "Wrong password." : e.message;
    } finally {
      submit.disabled = false;
    }
  });
  $("logout").addEventListener("click", async () => {
    try { await api("/api/logout", {}); } catch (_) { /* already gone */ }
    showLogin();
  });
  $("refresh").addEventListener("click", load);
  $("reload").addEventListener("click", async () => {
    try { await act({ action: "reload" }); await load(); } catch (e) { showBanner(`Reconcile failed: ${e.message}`); }
  });
  $("add-agent").addEventListener("click", inviteDialog);
  $("add-forward").addEventListener("click", forwardDialog);
  $("add-device").addEventListener("click", deviceDialog);
  $("modal-close").addEventListener("click", closeModal);
  $("modal").addEventListener("click", (event) => { if (event.target === $("modal")) closeModal(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("modal").hidden) closeModal(); });
  $("logs-box").addEventListener("toggle", () => { if ($("logs-box").open) loadLogs(); });
  $("diag-box").addEventListener("toggle", () => { if ($("diag-box").open) loadDiagnostics(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("app").hidden) load(); });
  try {
    const session = await api("/api/session");
    if (session.authenticated) await showApp(); else showLogin();
  } catch (_) {
    showLogin();
  }
});
