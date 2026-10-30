"use strict";

// All values from the server are written with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
const REFRESH_MS = 10000;
let timer = null;

async function api(path, body) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-Rift-Panel"] = "1";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  try { data = await response.json(); } catch (_) { /* empty body */ }
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("session expired");
  }
  if (!response.ok) throw new Error((data && data.error) || response.statusText);
  return data;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
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

function fill(tbody, rows, columns, emptyText) {
  tbody.replaceChildren();
  if (!rows.length) {
    tbody.append(el("tr", {}, el("td", { class: "empty", colspan: columns }, emptyText)));
    return;
  }
  for (const row of rows) tbody.append(row);
}

function actionButton(label, body, confirmText, kind) {
  return el("button", {
    type: "button",
    class: kind || "",
    onclick: async (event) => {
      if (confirmText && !window.confirm(confirmText)) return;
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await api("/api/action", body);
        await load();
      } catch (error) {
        showBanner(`Action failed: ${error.message}`);
        button.disabled = false;
      }
    },
  }, label);
}

function showBanner(text) {
  const banner = $("banner");
  banner.textContent = text;
  banner.hidden = !text;
}

function render(data) {
  const now = data.time;
  const agents = data.agents || [];
  const forwards = data.forwards || [];
  const peers = Array.isArray(data.vpn_peers) ? data.vpn_peers : [];
  const panel = data.panel || {};

  const state = $("state");
  if (data.apply_error) {
    state.replaceWith(Object.assign(pill("error", "bad"), { id: "state" }));
  } else if (data.fully_applied) {
    state.replaceWith(Object.assign(pill("applied", "ok"), { id: "state" }));
  } else {
    state.replaceWith(Object.assign(pill("applying", "warn"), { id: "state" }));
  }
  showBanner(data.apply_error ? `Last apply failed: ${data.apply_error}` : "");

  const active = agents.filter((a) => a.status === "active");
  $("t-agents").textContent = `${active.filter((a) => a.online).length} / ${active.length}`;
  $("t-forwards").textContent = `${forwards.filter((f) => f.enabled).length} / ${forwards.length}`;
  $("t-vpn").textContent = `${peers.filter((p) => p.enabled).length} / ${peers.length}`;
  $("t-panel").textContent = panel.access || "-";

  fill($("agents"), agents.map((a) => {
    const disabled = a.status === "disabled";
    const connection = a.status === "active"
      ? el("span", {}, el("span", { class: `dot ${a.online ? "ok" : "bad"}` }), a.online ? "online" : "offline")
      : el("span", { class: "muted" }, "-");
    const statePill = a.status === "active"
      ? (a.configuration_ready ? pill("active", "ok") : pill("syncing", "warn"))
      : a.status === "pending" ? pill("invited", "warn") : pill("disabled", "off");
    let button = null;
    if (a.status === "active") {
      button = actionButton("Disable", { action: "agent_enable", name: a.id, enabled: false },
        `Disable agent ${a.name}? Its forwards and VPN access stop until it is enabled again.`);
    } else if (disabled) {
      button = actionButton("Enable", { action: "agent_enable", name: a.id, enabled: true });
    }
    return el("tr", {},
      el("td", {}, a.name),
      el("td", {}, connection),
      el("td", {}, statePill, a.last_error ? el("span", { class: "muted small", title: a.last_error }, " ⚠") : null),
      el("td", {}, el("code", {}, a.tunnel_ipv4 || "-")),
      el("td", {}, a.status === "active" ? ago(a.last_handshake, now) : "-"),
      el("td", { class: "actions" }, button));
  }), 6, "No agents yet. Invite one on the server with rift agents add NAME.");

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
      el("td", { class: "actions" },
        f.enabled
          ? actionButton("Disable", { action: "forward_enable", id: f.id, enabled: false })
          : actionButton("Enable", { action: "forward_enable", id: f.id, enabled: true }),
        actionButton("Remove", { action: "forward_remove", id: f.id },
          `Remove forward ${f.id} (${endpoint(f.listen_ip, range(f.listen_ports))})? This cannot be undone.`, "danger")));
  }), 8, "No forwards configured.");

  fill($("vpn"), peers.map((p) => {
    const grants = (p.grants || []).map((g) => `${g.agent || "?"}: ${access(g.access)}`);
    if (p.panel) grants.unshift("panel");
    const toggle = p.enabled
      ? actionButton("Disable", { action: "vpn_peer_enable", name: p.name, enabled: false },
        `Disable ${p.name}? If you are connected through this device, you lose access to the panel.`)
      : actionButton("Enable", { action: "vpn_peer_enable", name: p.name, enabled: true });
    return el("tr", {},
      el("td", {}, p.name),
      el("td", {}, el("code", {}, p.ipv4)),
      el("td", {}, p.enabled ? pill("enabled", "ok") : pill("disabled", "off")),
      el("td", {}, ago(p.last_handshake, now)),
      el("td", { class: "wrap" }, grants.length ? grants.join("; ") : el("span", { class: "muted" }, "none")),
      el("td", { class: "actions" }, toggle));
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
    render(await api("/api/overview"));
  } catch (error) {
    if (error.message !== "session expired") showBanner(`Could not load: ${error.message}`);
  }
}

function schedule() {
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
}

function showLogin() {
  clearInterval(timer);
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
    const button = event.submitter || event.target.querySelector("button");
    button.disabled = true;
    $("login-error").textContent = "";
    try {
      await api("/api/login", { password: $("password").value });
      $("password").value = "";
      await showApp();
    } catch (error) {
      $("login-error").textContent = error.message === "wrong password" ? "Wrong password." : error.message;
    } finally {
      button.disabled = false;
    }
  });
  $("logout").addEventListener("click", async () => {
    try { await api("/api/logout", {}); } catch (_) { /* already gone */ }
    showLogin();
  });
  $("refresh").addEventListener("click", load);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("app").hidden) load(); });
  try {
    const session = await api("/api/session");
    if (session.authenticated) await showApp(); else showLogin();
  } catch (_) {
    showLogin();
  }
});
