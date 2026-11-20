"use strict";

// The RIFT web panel: the same sections as the terminal UI (rift without a command), as tabs
// with a table, the details of the selected row and its actions. All values from the server
// are written with textContent, never as HTML.
const $ = (id) => document.getElementById(id);
const REFRESH_MS = 5000;
const LOG_REFRESH_MS = 3000;
let timer = null;
let logTimer = null;
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

// Every change answers which devices' main profile it changed (`reimport`); they must import
// it again. Callers that say so themselves pass { quiet: true }.
const pendingImports = new Set();
async function act(body, options) {
  const result = await api("/api/action", body);
  const devices = (result && Array.isArray(result.reimport)) ? result.reimport : [];
  if (devices.length && !(options && options.quiet)) showReimport(devices);
  return result;
}

function showReimport(devices) {
  for (const d of devices) pendingImports.add(d);
  const box = $("reimport");
  const names = [...pendingImports];
  if (!names.length) { box.hidden = true; box.replaceChildren(); return; }
  box.replaceChildren(
    el("span", {}, `The WireGuard configuration of ${names.join(", ")} changed. Import it again on the device:`),
    ...names.map((n) => button(`${n}: QR code`, () => configDialog(n))),
    button("Dismiss", () => { pendingImports.clear(); showReimport([]); }, "ghost"));
  box.hidden = false;
}

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

function svg(tag, attrs, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
  for (const child of children) node.append(child);
  return node;
}

// A link that opens in a new tab. Only http(s) addresses become links, anything else stays text.
function link(href, text) {
  let url;
  try { url = new URL(href); } catch (_) { return text; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return text;
  return el("a", { href: url.href, target: "_blank", rel: "noopener noreferrer" }, text);
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

// Ports that are opened with https; every other TCP port is linked with http.
const HTTPS_PORTS = new Set([443, 8443, 9443]);

// The URL to open a single-port TCP forward at, or null (UDP, port ranges, no address).
function forwardUrl(forward) {
  const ports = forward.listen_ports;
  const ip = String(forward.listen_ip || "");
  if (forward.protocol !== "tcp" || !ports || ports.start !== ports.end) return null;
  if (!ip || ip === "0.0.0.0" || ip === "::") return null;
  const scheme = HTTPS_PORTS.has(ports.start) ? "https" : "http";
  const host = ip.includes(":") ? `[${ip}]` : ip;
  const port = (ports.start === 80 && scheme === "http") || (ports.start === 443 && scheme === "https") ? "" : `:${ports.start}`;
  return `${scheme}://${host}${port}/`;
}

function access(a) {
  if (a === "server") return "host";
  if (a === "full") return "host, all protocols";
  if (a === "dns") return "DNS server of the main profile (53/both)";
  if (a && a.port) return `port ${range(a.port.ports)}/${a.port.protocol}`;
  if (a && a.subnet) return `${a.subnet.net}${a.subnet.snat ? " (SNAT)" : ""}`;
  return JSON.stringify(a);
}

// One exit of a device as text: the main profile sends everything through this server,
// every agent exit is a separate extra profile.
function exitText(exit) {
  if (!exit || !exit.via) return "";
  if (exit.via === "server") return "main profile: all traffic through this server";
  const note = exit.state === "refused" ? " (refused by the agent)" : exit.state === "waiting" ? " (waiting for the agent)" : "";
  return `extra profile via ${exit.agent || "?"}${note}`;
}

// "main: exit via server · profiles: node1, node2 (refused)" for the devices table.
function exitSummary(peer) {
  const exits = peer.exits || [];
  const parts = [];
  if (exits.some((x) => x.via === "server")) parts.push("main: exit via server");
  const profiles = exits.filter((x) => x.via === "agent")
    .map((x) => `${x.agent || "?"}${x.state === "refused" ? " (refused)" : x.state === "waiting" ? " (waiting)" : ""}`);
  if (profiles.length) parts.push(`profiles: ${profiles.join(", ")}`);
  return parts.join(" · ");
}


function showBanner(text) {
  const banner = $("banner");
  banner.textContent = text || "";
  banner.hidden = !text;
}

let toastTimer = null;
function toast(text, kind) {
  const box = $("toast");
  box.className = `toast ${kind || "ok"}`;
  box.textContent = text;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, kind === "bad" ? 9000 : 5000);
}

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n || 0;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit += 1; }
  return unit ? `${value.toFixed(1)} ${units[unit]}` : `${value} B`;
}
const rate = (n) => `${bytes(n)}/s`;

function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.floor(s / 60) % 60} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor(s / 3600) % 24} h`;
}

// ---------- state ----------

const TABS = [
  { id: "overview", title: "Overview" },
  { id: "agents", title: "Agents", count: () => agentRows().length },
  { id: "forwards", title: "Forwards", count: () => (data.forwards || []).length },
  { id: "devices", title: "VPN devices", count: () => peers().length },
  { id: "sites", title: "Sites", count: () => ((data.sites || {}).sites || []).length },
  { id: "bans", title: "Bans", count: () => (data.bans || []).length },
  { id: "panel", title: "Web panel" },
  { id: "logs", title: "Logs" },
  { id: "health", title: "Health" },
  { id: "backup", title: "Backup" },
];

const state = {
  tab: "overview",
  selected: {},
  filter: {},
  sort: "id",
  focus: null,
  logs: { lines: [], follow: true, level: 0, text: "" },
  checks: null,
  traffic: { previous: null, at: 0, rx: [], tx: [], rates: {} },
};

const peers = () => (Array.isArray(data.vpn_peers) ? data.vpn_peers : []);

// Agents, and every open invitation of a name that has not enrolled yet as a row of its own.
function agentRows() {
  const rows = [...(data.agents || [])];
  for (const i of data.invites || []) {
    if (!rows.some((a) => a.name === i.name)) rows.push({ name: i.name, status: "invited", invite: true, expires_at: i.expires_at });
  }
  return rows;
}

function sampleTraffic() {
  const t = state.traffic;
  const now = Date.now() / 1000;
  const current = {};
  let rx = 0;
  let tx = 0;
  for (const p of data.peers || []) {
    current[p.public_key] = [p.rx_bytes || 0, p.tx_bytes || 0];
    const before = t.previous && t.previous[p.public_key];
    const elapsed = now - t.at;
    if (before && elapsed > 0.5) {
      const r = Math.max(0, (p.rx_bytes - before[0]) / elapsed);
      const s = Math.max(0, (p.tx_bytes - before[1]) / elapsed);
      t.rates[p.public_key] = [r, s];
      rx += r;
      tx += s;
    }
  }
  if (t.previous) {
    t.rx.push(rx);
    t.tx.push(tx);
    if (t.rx.length > 120) { t.rx.shift(); t.tx.shift(); }
  }
  t.previous = current;
  t.at = now;
}

// ---------- filters (the same rules as `rift list forwards` and the terminal UI) ----------

function words(text) {
  return String(text || "").toLowerCase().split(/[\s,]+/).filter(Boolean);
}

function textOf(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return Object.values(value).map(textOf).join("\n");
  return String(value).toLowerCase();
}

function forwardState(f) {
  if (f.refused) return "refused";
  if (!f.enabled) return "disabled";
  if (f.pending) return "pending";
  return "active";
}
const STATE_RANK = { active: 0, pending: 1, refused: 2, disabled: 3 };

function hasPort(f, port) {
  return ["listen_ports", "target_ports"].some((k) => f[k] && port >= f[k].start && port <= f[k].end);
}

function parseForwardQuery(text) {
  const q = { agents: [], port: null, proto: null, state: null, words: [], error: null };
  for (const w of words(text)) {
    const i = w.indexOf(":");
    const key = i > 0 ? w.slice(0, i) : "";
    const value = i > 0 ? w.slice(i + 1) : "";
    if (key === "agent" && value) q.agents.push(value);
    else if (key === "port") {
      if (/^\d+$/.test(value) && Number(value) <= 65535) q.port = Number(value);
      else q.error = `port:${value} is not a port number`;
    } else if (key === "proto" || key === "protocol") {
      if (value === "tcp" || value === "udp") q.proto = value;
      else q.error = "use proto:tcp or proto:udp";
    } else if (key === "state" && value) q.state = value;
    else q.words.push(w);
  }
  return q;
}

function forwardMatches(f, q) {
  const agent = String(f.agent || "").toLowerCase();
  if (q.agents.length && !q.agents.includes(agent)) return false;
  if (q.port !== null && !hasPort(f, q.port)) return false;
  if (q.proto && f.protocol !== q.proto) return false;
  if (q.state && !forwardState(f).startsWith(q.state)) return false;
  const fields = [agent, f.listen_ip, f.protocol, f.mode, f.ingress, f.purpose, forwardState(f), (f.allow_from || []).join(" ")]
    .map((v) => String(v || "").toLowerCase());
  return q.words.every((w) => (/^\d+$/.test(w)
    ? f.id === Number(w) || hasPort(f, Number(w))
    : fields.some((field) => field.includes(w))));
}

function deviceUses(device, agent) {
  const named = (x) => String(x.agent || "").toLowerCase() === agent.toLowerCase();
  return (device.grants || []).some(named) || (device.exits || []).some(named);
}

// The rows of a table tab after the agent focus, the filter and (forwards) the order.
function rows(tab) {
  let list;
  if (tab === "agents") list = agentRows();
  else if (tab === "forwards") list = [...(data.forwards || [])];
  else if (tab === "devices") list = [...peers()];
  else if (tab === "sites") list = [...((data.sites || {}).sites || [])];
  else if (tab === "bans") list = [...(data.bans || [])];
  else return [];
  const focus = state.focus;
  if (focus && tab !== "agents") {
    list = tab === "devices" ? list.filter((d) => deviceUses(d, focus))
      : list.filter((x) => String(x.agent || "").toLowerCase() === focus.toLowerCase());
  }
  const text = state.filter[tab] || "";
  if (tab === "forwards") {
    const q = parseForwardQuery(text);
    if (!q.error) list = list.filter((f) => forwardMatches(f, q));
    const port = (f) => (f.listen_ports ? f.listen_ports.start : 0);
    const by = {
      id: (a, b) => a.id - b.id,
      agent: (a, b) => String(a.agent).localeCompare(String(b.agent)) || port(a) - port(b) || a.id - b.id,
      port: (a, b) => port(a) - port(b) || a.id - b.id,
      state: (a, b) => STATE_RANK[forwardState(a)] - STATE_RANK[forwardState(b)] || a.id - b.id,
    }[state.sort];
    list.sort(by);
  } else if (text) {
    const ws = words(text);
    list = list.filter((item) => { const t = textOf(item); return ws.every((w) => t.includes(w)); });
  }
  return list;
}

const KEYS = {
  agents: (a) => (a.invite ? `invite:${a.name}` : a.id),
  forwards: (f) => String(f.id),
  devices: (d) => d.name,
  sites: (s) => s.host,
  bans: (b) => String(b.id),
};

function selected(tab) {
  const list = rows(tab);
  const key = state.selected[tab];
  return list.find((item) => KEYS[tab](item) === key) || list[0] || null;
}

// ---------- small pieces ----------

const dot = (kind) => el("span", { class: `dot ${kind}` });

function kv(label, value) {
  return el("div", { class: "kv" }, el("span", { class: "k" }, label), el("span", { class: "v" }, value));
}

function card(title, value, sub, kind) {
  return el("div", { class: "card stat" },
    el("span", { class: "stat-title" }, title),
    el("span", { class: `stat-value ${kind || ""}` }, value),
    el("span", { class: "stat-sub muted" }, sub));
}

function panelBox(title, ...children) {
  return el("section", { class: "box" }, title ? el("h2", {}, title) : null, ...children);
}

// The traffic of the last samples as two lines (in, out) in one SVG.
function chart(rx, tx) {
  const w = 600;
  const h = 90;
  const n = Math.max(rx.length, 2);
  const max = Math.max(1, ...rx, ...tx);
  const line = (values) => values.map((v, i) => `${((i / (n - 1)) * w).toFixed(1)},${(h - (v / max) * (h - 6) - 3).toFixed(1)}`).join(" ");
  const area = (values, cls) => (values.length > 1
    ? svg("polygon", { class: cls, points: `0,${h} ${line(values)} ${(((values.length - 1) / (n - 1)) * w).toFixed(1)},${h}` })
    : null);
  const node = svg("svg", { viewBox: `0 0 ${w} ${h}`, preserveAspectRatio: "none", class: "chart", role: "img", "aria-label": "Traffic through the tunnel" });
  for (const part of [area(rx, "area-in"), area(tx, "area-out")]) if (part) node.append(part);
  if (rx.length > 1) node.append(svg("polyline", { class: "line-in", points: line(rx) }), svg("polyline", { class: "line-out", points: line(tx) }));
  return node;
}

function agentRates() {
  const out = {};
  for (const a of data.agents || []) {
    const r = state.traffic.rates[a.public_key];
    if (r) out[a.id] = r;
  }
  return out;
}

function agentState(a) {
  if (a.invite) return ["warn", "invited"];
  if (a.status === "pending") return ["warn", "enrolling"];
  if (a.status !== "active") return ["off", a.status || "?"];
  if (!a.online) return ["bad", "offline"];
  return a.configuration_ready ? ["ok", "online"] : ["warn", "syncing"];
}

// What needs attention, as on the terminal UI's overview.
function attention() {
  const now = data.time;
  const items = [];
  const push = (kind, text) => items.push(el("li", { class: kind }, text));
  if (data.apply_error) push("bad", `Configuration not applied: ${data.apply_error}`);
  if ((data.panel || {}).error) push("bad", `Web panel ${data.panel.error}`);
  for (const a of data.agents || []) {
    if (a.status === "active" && !a.online) push("warn", `Agent ${a.name} is offline`);
    else if (a.status === "active" && !a.configuration_ready) push("warn", `Agent ${a.name} has not applied the latest configuration`);
    if (a.last_error) push("warn", `Agent ${a.name}: ${a.last_error}`);
  }
  for (const f of data.forwards || []) if (f.refused && f.enabled) push("warn", `Forward ${f.id} refused by ${f.agent}: ${f.refused}`);
  for (const g of data.refused_grants || []) push("warn", `Access of ${g.device} to ${g.agent} (${access(g.access)}) refused by the agent: ${g.reason}`);
  for (const g of data.refused_host_grants || []) push("warn", `Access of this server to ${g.agent} (${access(g.access)}) refused by the agent: ${g.reason}`);
  for (const i of data.invites || []) push("info", `Invitation for ${i.name} open, ${duration(i.expires_at - now)} left`);
  if ((data.sites || {}).available === false && (data.sites || {}).queue === false) push("muted", "Sites: the host helper is not installed (sudo sh deploy/install-cli)");
  return items;
}

// One structured log line: time, level, message and fields.
function logLine(raw, full) {
  let entry;
  try { entry = JSON.parse(raw); } catch (_) { return { rank: 1, node: el("div", { class: "log" }, raw) }; }
  const level = String(entry.level || "INFO");
  const rank = { ERROR: 3, WARN: 2, INFO: 1 }[level] ?? 0;
  const fields = entry.fields || {};
  const time = String(entry.timestamp || "").split("T")[1] || "";
  const extra = Object.entries(fields).filter(([k]) => k !== "message").map(([k, v]) => el("span", { class: "field" }, ` ${k}=`, el("b", {}, typeof v === "object" ? JSON.stringify(v) : String(v))));
  return {
    rank,
    node: el("div", { class: "log" },
      el("span", { class: "muted" }, time.slice(0, 8), " "),
      el("span", { class: `level ${level.toLowerCase()}` }, level.padEnd(5), " "),
      fields.message || "", ...extra,
      full && entry.target ? el("span", { class: "muted" }, `  (${entry.target})`) : null),
  };
}

// ---------- actions of the current tab ----------

// Every action of the tab for the selected row: key, label, run, and `write` when it changes
// something (hidden on a read-only connection).
function actions() {
  const item = selected(state.tab);
  const list = [];
  const add = (key, label, run, options) => list.push({ key, label, run, ...(options || {}) });
  const w = { write: true };
  switch (state.tab) {
    case "overview":
      add("a", "Invite agent", () => inviteDialog(), w);
      add("f", "Add forward", forwardDialog, w);
      add("d", "Connect device", deviceDialog, w);
      break;
    case "agents":
      add("a", "Invite", () => inviteDialog(), w);
      if (item && item.invite) {
        add("t", "New token", () => newToken(item.name), w);
        add("c", "Cancel invitation", () => confirmAct(`Cancel the invitation for ${item.name}?`, { action: "agent_cancel_invite", name: item.name }), { write: true, danger: true });
      } else if (item) {
        if (item.status === "active") add("e", "Disable", () => confirmAct(`Disable ${item.name}? Its forwards and VPN access stop until it is enabled again.`, { action: "agent_enable", name: item.id, enabled: false }), w);
        else if (item.status === "disabled") add("e", "Enable", () => runAct({ action: "agent_enable", name: item.id, enabled: true }), w);
        if (item.status === "active") add("f", "Add forward", () => forwardDialog(item.name), w);
        if (item.status === "active" || (item.host_grants || []).length) add("h", "Server access", () => hostDialog(item.name), w);
        add("r", "Rename", () => renameDialog(item), w);
        if (item.status !== "pending") add("K", "Rotate key", () => confirmAct(`Give ${item.name} a new WireGuard key? It happens on the agent's next sync.`, { action: "agent_rotate", name: item.id }), w);
        if (item.dns_name) add("n", item.names ? "Names off" : "Names on", () => namesChange({ action: "agent_names", name: item.id, on: !item.names }), w);
        if (item.status === "active") add("i", "Invite again", () => inviteDialog(item.name), w);
        add("x", "Remove", () => confirmAct(`Remove ${item.name} with all its forwards and VPN grants? This cannot be undone.`, { action: "agent_remove", name: item.id }), { write: true, danger: true });
      }
      break;
    case "forwards":
      add("a", "Add", () => forwardDialog(), w);
      if (item && item.purpose !== "exit") {
        add("e", item.enabled ? "Disable" : "Enable", () => runAct({ action: "forward_enable", id: item.id, enabled: !item.enabled }), w);
        if (item.mode === "translate") add("b", "Ban a client", () => banDialog(item), w);
        const url = forwardUrl(item);
        if (url) add("o", "Open", () => window.open(url, "_blank", "noopener"));
        add("x", "Remove", () => confirmAct(`Remove forward ${item.id} (${endpoint(item.listen_ip, range(item.listen_ports))})? This cannot be undone.`, { action: "forward_remove", id: item.id }), { write: true, danger: true });
      }
      break;
    case "devices":
      add("a", "Connect device", deviceDialog, w);
      if (item) {
        add("g", "Access", () => grantsDialog(item.name), w);
        add("c", "Config / QR", () => configDialog(item.name), w);
        add("e", item.enabled ? "Disable" : "Enable", () => (item.enabled
          ? confirmAct(`Disable ${item.name}? If you are connected through it, you lose the panel.`, { action: "vpn_peer_enable", name: item.name, enabled: false })
          : runAct({ action: "vpn_peer_enable", name: item.name, enabled: true })), w);
        add("x", "Remove", () => confirmAct(`Remove ${item.name}? Its key and all grants are deleted. If you are connected through it, you lose the panel.`, { action: "vpn_peer_revoke", name: item.name }), { write: true, danger: true });
      }
      break;
    case "sites":
      add("a", "Add site", siteDialog, w);
      if (item) {
        add("o", "Open", () => window.open(`https://${item.host}`, "_blank", "noopener"));
        add("x", "Remove", () => removeSite(item), { write: true, danger: true });
      }
      break;
    case "panel": {
      const factor = data.two_factor || {};
      if (!factor.required) add("s", factor.enabled ? "Turn 2FA off" : "Set up 2FA", factor.enabled ? twoFactorOffDialog : twoFactorDialog, w);
      add("g", "Grant a device", () => panelDevices(true), w);
      add("w", "Withdraw a device", () => panelDevices(false), w);
      break;
    }
    case "logs":
      add("f", state.logs.follow ? "Pause" : "Follow", () => { state.logs.follow = !state.logs.follow; render(); });
      add("v", ["All levels", "Info and up", "Warnings and up", "Errors only"][state.logs.level], () => { state.logs.level = (state.logs.level + 1) % 4; render(); });
      break;
    case "health":
      add("r", "Run checks", loadChecks);
      break;
    case "backup":
      add("e", "Export settings", exportDialog, w);
      add("i", "Import settings", importDialog, w);
      add("b", "Download backup", backupDialog, { write: true, danger: true });
      break;
    default:
  }
  return list.filter((a) => canWrite || !a.write);
}

async function runAct(body) {
  try {
    await act(body);
    await load();
    toast("Done.");
  } catch (e) { toast(e.message, "bad"); }
}

function confirmAct(text, body) {
  confirmDialog(text, () => runAct(body), body.action.endsWith("remove") || body.action.endsWith("revoke"));
}

function confirmDialog(text, run, danger) {
  openModal("Confirm",
    el("p", {}, text),
    el("div", { class: "form" }, el("div", { class: "buttons" },
      button("Cancel", closeModal),
      button("Yes", () => { closeModal(); run(); }, danger ? "danger" : "primary"))));
}

function renameDialog(agent) {
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", value: agent.name });
  openModal(`Rename ${agent.name}`, form([
    row("New name", name),
    el("p", { class: "hint" }, `Its DNS name follows: ${agent.dns_name || "NAME"} becomes NEW.${data.names_suffix || "internal"}. Devices need nothing new.`),
  ], "Rename", async () => {
    await act({ action: "agent_rename", name: agent.id, new_name: name.value.trim() });
    closeModal();
    await load();
  }));
}

// A new token for an open invitation: the old one is cancelled.
function newToken(name) {
  confirmDialog(`Replace the invitation for ${name} with a new one, valid for 15 minutes? The old token stops working.`, async () => {
    try {
      await act({ action: "agent_cancel_invite", name });
      const result = await act({ action: "agent_invite", name, ttl: "15m" });
      await load();
      showInvitation(result);
    } catch (e) { toast(e.message, "bad"); }
  });
}

async function removeSite(site) {
  confirmDialog(`Remove the site ${site.host} and its forward?`, async () => {
    try {
      const queued = await act({ action: "site_remove", host: site.host });
      await awaitSite(queued.id, `Removing ${site.host}`);
    } catch (e) { toast(e.message, "bad"); }
  }, true);
}

function panelDevices(grant) {
  const list = peers().filter((p) => !!p.panel !== grant);
  if (!list.length) {
    toast(grant ? "Every device may open the panel already, or there is none." : "No device may open the panel.");
    return;
  }
  menuAt(null, list.map((p) => ({
    label: p.name,
    run: () => runAct({ action: "panel_allow", name: p.name, allowed: grant }),
  })), grant ? "Let a device open the panel" : "Withdraw panel access");
}

function focusMenu(anchor) {
  const names = (data.agents || []).map((a) => a.name);
  menuAt(anchor, [
    { label: "All agents", hint: state.focus ? "" : "shown", run: () => setFocus(null) },
    ...names.map((n) => ({ label: n, hint: state.focus === n ? "shown" : "", run: () => setFocus(n) })),
  ], "Show forwards, devices, sites and bans of");
}

function setFocus(agent) {
  state.focus = agent;
  render();
}

// ---------- menu (right click, focus, choices) ----------

function menuAt(anchor, items, title) {
  const menu = $("menu");
  menu.replaceChildren(
    ...(title ? [el("div", { class: "menu-title" }, title)] : []),
    ...items.map((item) => el("button", {
      type: "button",
      role: "menuitem",
      class: item.danger ? "danger-text" : "",
      onclick: () => { closeMenu(); item.run(); },
    }, el("span", {}, item.label), item.hint ? el("kbd", {}, item.hint) : null)));
  menu.hidden = false;
  const box = menu.getBoundingClientRect();
  let x = window.innerWidth / 2 - box.width / 2;
  let y = window.innerHeight / 3;
  if (anchor && anchor.clientX !== undefined) { x = anchor.clientX; y = anchor.clientY; }
  else if (anchor && anchor.getBoundingClientRect) { const r = anchor.getBoundingClientRect(); x = r.left; y = r.bottom + 4; }
  menu.style.left = `${Math.max(8, Math.min(x, window.innerWidth - box.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, window.innerHeight - box.height - 8))}px`;
  const first = menu.querySelector("button");
  if (first) first.focus();
}

function closeMenu() {
  $("menu").hidden = true;
}

// ---------- rendering ----------

function setPill(id, text, kind) {
  const node = $(id);
  node.className = `pill ${kind}`;
  node.textContent = text;
}

function renderTabs() {
  const nav = $("tabs");
  nav.replaceChildren(...TABS.map((t, i) => {
    const count = t.count ? t.count() : 0;
    return el("button", {
      type: "button",
      class: `tab ${state.tab === t.id ? "active" : ""}`,
      "aria-current": state.tab === t.id ? "page" : null,
      onclick: () => switchTab(t.id),
    }, el("kbd", {}, String((i + 1) % 10)), t.title, count ? el("span", { class: "count" }, String(count)) : null);
  }), ...(state.focus ? [el("button", { type: "button", class: "focus-chip", onclick: (e) => focusMenu(e.currentTarget), title: "Focus on one agent (F)" }, `◉ agent ${state.focus}`)] : []));
}

function switchTab(id) {
  if (!TABS.some((t) => t.id === id)) return;
  state.tab = id;
  if (location.hash !== `#${id}`) history.replaceState(null, "", `#${id}`);
  renderToolbar();
  render();
  if (id === "logs" || id === "overview") loadLogs();
  if (id === "health" && !state.checks) loadChecks();
}

// The search box and, on Forwards, the order. Built once per tab, so typing keeps its focus.
function renderToolbar() {
  const bar = $("toolbar");
  const tab = state.tab;
  if (!["agents", "forwards", "devices", "sites", "bans", "logs"].includes(tab)) {
    bar.replaceChildren();
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  const value = tab === "logs" ? state.logs.text : (state.filter[tab] || "");
  const input = el("input", {
    id: "filter",
    type: "search",
    value,
    placeholder: tab === "forwards" ? "Filter: homelab 8080 udp · agent:NAME port:N proto:tcp state:pending" : "Filter: words that must all appear",
    "aria-label": "Filter",
  });
  input.addEventListener("input", () => {
    if (tab === "logs") state.logs.text = input.value; else state.filter[tab] = input.value;
    render();
  });
  const parts = [el("span", { class: "search-icon" }, "⌕"), input];
  if (tab === "forwards") {
    const sort = select([["id", "Sort: ID"], ["agent", "Sort: agent"], ["port", "Sort: port"], ["state", "Sort: state"]], state.sort);
    sort.addEventListener("change", () => { state.sort = sort.value; render(); });
    parts.push(sort);
  }
  if (tab !== "logs" && tab !== "agents") {
    parts.push(button(state.focus ? `◉ ${state.focus}` : "All agents", (e) => focusMenu(e.currentTarget), "ghost"));
  }
  parts.push(el("span", { id: "filter-count", class: "muted small" }));
  bar.replaceChildren(...parts);
}

function render() {
  if (!data) return;
  canWrite = !!data.can_write;
  for (const node of document.querySelectorAll(".write")) node.hidden = !canWrite;
  $("readonly").hidden = canWrite;
  setPill("access", canWrite ? "full access" : "read-only", canWrite ? "ok" : "off");
  if (data.apply_error) setPill("state", "apply error", "bad");
  else if (data.fully_applied) setPill("state", "applied", "ok");
  else setPill("state", "applying", "warn");
  $("server").textContent = data.endpoint ? `server ${data.endpoint}` : "server";
  $("version").textContent = data.rift_version ? `v${data.rift_version}` : "";
  $("updated").textContent = new Date().toLocaleTimeString();
  renderTabs();

  const view = $("view");
  const scroller = view.querySelector(".table-scroll");
  const scroll = scroller ? scroller.scrollTop : 0;
  const draw = {
    overview: drawOverview, agents: drawAgents, forwards: drawForwards, devices: drawDevices,
    sites: drawSites, bans: drawBans, panel: drawPanel, logs: drawLogs, health: drawHealth, backup: drawBackup,
  }[state.tab];
  view.replaceChildren(...[draw()].flat());
  const next = view.querySelector(".table-scroll");
  if (next) next.scrollTop = scroll;
  renderActions();
}

function renderActions() {
  const bar = $("actionbar");
  const list = actions();
  bar.replaceChildren(
    el("div", { class: "actions-left" }, ...list.map((a) => el("button", {
      type: "button",
      class: `action ${a.danger ? "danger" : ""}`,
      onclick: () => a.run(),
      title: `${a.label} (${a.key})`,
    }, el("kbd", {}, a.key), a.label))),
    el("div", { class: "actions-right" },
      el("button", { type: "button", class: "action ghost", onclick: helpDialog }, el("kbd", {}, "?"), "Keys")));
}

// A table with a selectable row, and beside it (below on narrow screens) the details.
function table(tab, columns, list, empty, detail) {
  const current = selected(tab);
  const body = el("tbody", {});
  for (const item of list) {
    const key = KEYS[tab](item);
    const tr = el("tr", { class: current && KEYS[tab](current) === key ? "selected" : "", tabindex: "-1" },
      ...columns.map((c) => el("td", { class: c.cls || "" }, c.cell(item))));
    tr.addEventListener("click", () => { state.selected[tab] = key; render(); });
    tr.addEventListener("dblclick", () => { state.selected[tab] = key; render(); const first = actions().find((a) => a.key !== "a"); if (first) first.run(); });
    tr.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      state.selected[tab] = key;
      render();
      menuAt(event, actions().map((a) => ({ label: a.label, hint: a.key, run: a.run, danger: a.danger })));
    });
    body.append(tr);
  }
  const total = { agents: agentRows().length, forwards: (data.forwards || []).length, devices: peers().length, sites: ((data.sites || {}).sites || []).length, bans: (data.bans || []).length }[tab];
  const count = $("filter-count");
  if (count) count.textContent = list.length === total ? `${total}` : `${list.length} of ${total}`;
  const content = list.length
    ? el("div", { class: "table-scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ...columns.map((c) => el("th", { class: c.cls || "" }, c.title)))), body))
    : el("p", { class: "empty" }, total ? "Nothing matches the filter." : empty);
  return el("div", { class: "split" },
    el("section", { class: "box list" }, content),
    el("aside", { class: "box detail" }, current ? detail(current) : el("p", { class: "muted" }, "Nothing selected.")));
}

// ---------- tabs ----------

function drawOverview() {
  const now = data.time;
  const agents = data.agents || [];
  const forwards = data.forwards || [];
  const devices = peers();
  const enrolled = agents.length;
  const online = agents.filter((a) => a.online).length;
  const active = forwards.filter((f) => forwardState(f) === "active").length;
  const problems = forwards.filter((f) => f.enabled && (f.pending || f.refused)).length;
  const connected = devices.filter((d) => d.last_handshake && now - d.last_handshake <= 180).length;
  const sites = ((data.sites || {}).sites || []).length;
  const bans = (data.bans || []).length;
  const enrollment = data.enrollment || {};
  const rates = agentRates();
  const t = state.traffic;
  const last = (list) => (list.length ? list[list.length - 1] : 0);
  const items = attention();
  const logs = state.logs.lines.slice(-8).map((l) => logLine(l, false).node);
  return [
    el("div", { class: "stats" },
      card("Agents", `${online} / ${enrolled}`, `online · ${(data.invites || []).length} invitation(s) open`, online === enrolled ? "ok" : "warn"),
      card("Forwards", `${active} / ${forwards.length}`, problems ? `${problems} pending or refused` : "active · all applied", problems ? "warn" : "sky"),
      card("VPN devices", `${connected} / ${devices.length}`, `connected · ${devices.filter((d) => d.panel).length} with panel access`, "violet"),
      card("Sites · Bans", `${sites} · ${bans}`, enrollment.open ? "enrollment port open" : `enrollment ${enrollment.mode || "-"}`, "accent")),
    panelBox("Traffic through the tunnel",
      el("div", { class: "traffic" },
        el("div", { class: "legend" },
          el("div", {}, el("span", { class: "muted" }, "↓ in (received)"), el("strong", { class: "in" }, rate(last(t.rx)))),
          el("div", {}, el("span", { class: "muted" }, "↑ out (sent)"), el("strong", { class: "out" }, rate(last(t.tx))))),
        t.rx.length > 2 ? chart(t.rx, t.tx) : el("p", { class: "muted chart-wait" }, "Collecting samples…"))),
    el("div", { class: "two" },
      panelBox("Agents", el("ul", { class: "plain agents" }, agentRows().map((a) => {
        const [kind, label] = agentState(a);
        const r = rates[a.id];
        return el("li", { onclick: () => { state.selected.agents = KEYS.agents(a); switchTab("agents"); } },
          dot(kind), el("strong", {}, a.name), el("span", { class: "muted" }, label),
          a.invite ? el("span", { class: "accent" }, `token valid ${duration(a.expires_at - now)}`)
            : r ? el("span", { class: "rates" }, el("span", { class: "in" }, `↓${rate(r[0])}`), el("span", { class: "out" }, `↑${rate(r[1])}`)) : null);
      }), agents.length || (data.invites || []).length ? null : el("li", { class: "muted" }, "No agents yet. Invite one with a."))),
      panelBox("Attention", items.length ? el("ul", { class: "plain attention" }, items) : el("p", { class: "ok-text" }, "✓ Nothing needs attention."))),
    panelBox("Recent log", logs.length ? el("div", { class: "logs short" }, logs) : el("p", { class: "muted" }, "No entries yet.")),
  ];
}

function drawAgents() {
  const now = data.time;
  const rates = agentRates();
  const columns = [
    { title: "Name", cell: (a) => [dot(agentState(a)[0]), el("strong", {}, a.name)] },
    { title: "State", cell: (a) => agentState(a)[1] },
    { title: "Tunnel", cell: (a) => (a.tunnel_ipv4 ? el("code", {}, a.tunnel_ipv4) : "-") },
    { title: "Handshake", cls: "hide-s", cell: (a) => (a.invite ? "-" : a.last_handshake ? ago(a.last_handshake, now) : "never") },
    { title: "Traffic", cls: "hide-m", cell: (a) => (a.invite ? el("span", { class: "accent" }, `token valid ${duration(a.expires_at - now)}`)
      : rates[a.id] ? el("span", { class: "rates" }, el("span", { class: "in" }, `↓${rate(rates[a.id][0])}`), el("span", { class: "out" }, `↑${rate(rates[a.id][1])}`)) : "") },
    { title: "Version", cls: "hide-m", cell: (a) => a.rift_version || "-" },
  ];
  return table("agents", columns, rows("agents"), "No agents yet. Invite the first one with a.", (a) => {
    if (a.invite) {
      const enrollment = data.enrollment || {};
      return [el("h2", {}, a.name),
        el("p", { class: "accent" }, "◷ Invitation open, not enrolled yet"),
        kv("Valid for", duration(a.expires_at - now)),
        kv("Until", new Date(a.expires_at * 1000).toLocaleTimeString()),
        kv("Enrollment", `${enrollment.open ? "open" : "closed"} on ${enrollment.bind || "-"}`),
        el("p", { class: "hint" }, "Run the deploy/join line shown when the invitation was created on the agent host. The token is shown only then: New token makes another one, the old one stops working.")];
    }
    const limits = a.limits;
    const ports = !limits ? null : limits.ports === null || limits.ports === undefined ? "any"
      : limits.ports.length ? limits.ports.map((p) => `${range(p.ports)}${p.protocol ? `/${p.protocol}` : ""}`).join(", ") : "none";
    const forwards = (data.forwards || []).filter((f) => f.agent === a.name).length;
    return [el("h2", {}, a.name),
      kv("State", agentState(a)[1]),
      kv("IPv4", el("code", {}, a.tunnel_ipv4 || "-")),
      kv("IPv6", el("code", {}, a.tunnel_ipv6 || "-")),
      kv("DNS name", a.dns_name ? [el("code", {}, a.dns_name), el("span", { class: a.names ? "ok-text" : "muted" }, a.names ? " on" : " off")] : "-"),
      kv("Version", a.rift_version || "-"),
      kv("ID", el("code", { class: "small" }, a.id)),
      limits ? el("h3", {}, "What the agent allows") : null,
      limits ? kv("Ports", ports) : null,
      limits ? kv("LANs", (limits.subnets || []).join(", ") || "none") : null,
      limits ? kv("Exit", limits.exit ? "offered" : "not offered") : null,
      el("h3", {}, "Server host access"),
      ...((a.host_grants || []).length
        ? a.host_grants.map((g) => kv(access(g.access), g.refused
          ? el("span", { class: "error", title: g.refused }, "refused by the agent")
          : el("span", { class: "ok-text" }, "allowed")))
        : [el("p", { class: "muted" }, "None: the VPS host reaches nothing on this agent (h allows ports).")]),
      hostNameRow(a),
      a.last_error ? el("p", { class: "error" }, `✗ ${a.last_error}`) : null,
      el("p", { class: "muted" }, `${forwards} forward(s)`),
      a.dns_name ? el("p", { class: "hint" }, a.names
        ? `Devices with a grant on ${a.name} reach it as ${a.dns_name}.`
        : `Names on (n) makes ${a.dns_name} resolve for devices with a grant on ${a.name}.`) : null];
  });
}

function drawForwards() {
  const q = parseForwardQuery(state.filter.forwards || "");
  const columns = [
    { title: "ID", cls: "muted", cell: (f) => String(f.id) },
    { title: "Agent", cell: (f) => el("strong", {}, f.agent || "-") },
    { title: "Listen", cell: (f) => { const text = `${endpoint(f.listen_ip, range(f.listen_ports))}/${f.protocol}`; const url = forwardUrl(f); return el("code", {}, url ? link(url, text) : text); } },
    { title: "Target", cell: (f) => `→ ${range(f.target_ports)}${f.mode === "translate" ? ` ${f.target_family}` : ""}${f.purpose === "exit" ? " (exit)" : ""}` },
    { title: "Mode", cls: "hide-m", cell: (f) => f.mode },
    { title: "Access", cls: "hide-m", cell: (f) => `${f.ingress}${(f.allow_from || []).length ? `, only ${f.allow_from.join(" ")}` : ""}` },
    { title: "State", cell: (f) => { const s = forwardState(f); return [dot({ active: "ok", pending: "warn", refused: "bad", disabled: "off" }[s]), s]; } },
  ];
  const out = table("forwards", columns, rows("forwards"), "No forwards yet. Publish a port of an agent with a.", (f) => [
    el("h2", {}, `Forward ${f.id}`),
    kv("Agent", f.agent),
    kv("Listen", el("code", {}, `${endpoint(f.listen_ip, range(f.listen_ports))}/${f.protocol}`)),
    kv("Target", `${f.agent} port ${range(f.target_ports)} (${f.target_family})`),
    kv("Mode", f.mode === "translate" ? "translate (IPv4 ⇄ IPv6; the service sees this server)" : "transparent (the service sees the client)"),
    kv("Ingress", f.ingress),
    kv("Clients", (f.allow_from || []).length ? `only ${f.allow_from.join(", ")}` : "everyone"),
    kv("State", forwardState(f)),
    f.purpose === "exit" ? el("p", { class: "hint" }, "Managed by RIFT for an internet exit.") : null,
    f.refused ? el("p", { class: "error" }, `✗ ${f.refused}`) : null,
  ]);
  if (q.error) out.prepend(el("p", { class: "error" }, q.error));
  return out;
}

function drawDevices() {
  const now = data.time;
  const columns = [
    { title: "Name", cell: (d) => { const on = d.last_handshake && now - d.last_handshake <= 180; return [dot(!d.enabled ? "off" : on ? "ok" : "idle"), el("strong", {}, d.name)]; } },
    { title: "Address", cell: (d) => el("code", {}, d.ipv4) },
    { title: "State", cls: "hide-s", cell: (d) => (d.enabled ? "enabled" : "disabled") },
    { title: "Handshake", cls: "hide-s", cell: (d) => ago(d.last_handshake, now) },
    { title: "Access", cls: "hide-m wrap", cell: (d) => {
      const g = (d.grants || []).map((x) => x.refused ? el("span", { class: "error", title: x.refused }, `${x.agent}: ${access(x.access)} ✗`) : `${x.agent}: ${access(x.access)}`);
      if (d.panel) g.unshift("panel");
      return g.length ? g.flatMap((x, i) => (i ? ["; ", x] : [x])) : el("span", { class: "muted" }, "none");
    } },
  ];
  return table("devices", columns, rows("devices"), "No VPN devices yet. Connect a phone or laptop with a.", (d) => [
    el("h2", {}, d.name),
    kv("IPv4", el("code", {}, d.ipv4)),
    kv("IPv6", el("code", {}, d.ipv6 || "-")),
    kv("State", `${d.enabled ? "enabled" : "disabled"} · handshake ${ago(d.last_handshake, now)}`),
    kv("Panel", d.panel ? "may open it" : "no"),
    kv("Names", d.names_off ? "off" : (d.names || []).join(", ") || "on (none reachable)"),
    el("h3", {}, "Access"),
    (d.grants || []).length
      ? el("ul", { class: "plain grants" }, d.grants.map((g) => el("li", {}, el("span", { class: "accent" }, g.agent || "?"), `: ${access(g.access)}`, g.refused ? el("span", { class: "error" }, ` ✗ ${g.refused}`) : null)))
      : el("p", { class: "muted" }, "Nothing yet: Access (g) grants ports, a LAN, the host or an exit."),
    (d.exits || []).length ? el("h3", {}, "Internet exits") : null,
    (d.exits || []).length ? el("ul", { class: "plain" }, d.exits.map((x) => el("li", {}, exitText(x)))) : null,
    kv("Key", el("code", { class: "small" }, d.public_key || "-")),
  ]);
}

function drawSites() {
  const sites = data.sites || {};
  const proxy = sites.proxy || {};
  const columns = [
    { title: "Domain", cell: (s) => el("strong", {}, link(`https://${s.host}`, s.host)) },
    { title: "Agent", cell: (s) => s.agent },
    { title: "Target", cell: (s) => String(s.target) },
    { title: "Proxy", cls: "hide-s", cell: (s) => s.proxy },
    { title: "Forward", cell: (s) => [dot(s.forward === "ok" ? "ok" : s.forward === "refused" ? "bad" : "warn"), s.forward] },
    { title: "Only from", cls: "hide-m", cell: (s) => (s.allow_from || []).join(" ") || "everyone" },
  ];
  const out = table("sites", columns, rows("sites"),
    sites.available === false && sites.queue === false
      ? "Sites are managed by the host helper, which is not installed: sudo sh deploy/install-cli on the server."
      : "No sites yet. Publish a domain through the reverse proxy with a.",
    (s) => [el("h2", {}, s.host),
      kv("Agent", s.agent), kv("Target port", String(s.target)), kv("Listen port", String(s.listen)),
      kv("Proxy", s.proxy), kv("Forward", `${s.forward}${s.forward_id ? ` (#${s.forward_id})` : ""}`),
      kv("Only from", (s.allow_from || []).join(", ") || "everyone"),
      s.reason ? el("p", { class: "error" }, s.reason) : null]);
  if (proxy.name) {
    out.prepend(el("p", { class: "muted small proxy-line" }, `Proxy: ${proxy.name}${proxy.name === "caddy" && proxy.caddy_sites_dir
      ? (proxy.caddy_container ? ` in container ${proxy.caddy_container}, sites in ${proxy.caddy_sites_dir}` : ` on the host, sites in ${proxy.caddy_sites_dir}`) : ""}`));
  }
  return out;
}

function drawBans() {
  const now = data.time;
  const columns = [
    { title: "Address", cell: (b) => el("code", {}, b.ip) },
    { title: "Agent", cell: (b) => b.agent },
    { title: "Forward", cell: (b) => String(b.forward_id) },
    { title: "Expires", cell: (b) => `in ${duration(b.expires_at - now)}` },
  ];
  return table("bans", columns, rows("bans"), "No active bans. Bans block client addresses on translated forwards (Forwards → b).", (b) => [
    el("h2", {}, b.ip), kv("Agent", b.agent), kv("Forward", String(b.forward_id)), kv("Expires", new Date(b.expires_at * 1000).toLocaleString()),
  ]);
}

function drawPanel() {
  const panel = data.panel || {};
  const factor = data.two_factor || {};
  const running = !panel.error && (panel.listening || []).length;
  return el("div", { class: "two" },
    panelBox("Web panel",
      kv("Status", el("span", { class: panel.error ? "error" : running ? "ok-text" : "warn-text" }, panel.error ? "on, but not running" : running ? "running" : "starting")),
      kv("Listens", panel.access || "-"), kv("Changes", panel.control || "-"), kv("Port", String(panel.port || "-")),
      panel.error ? el("p", { class: "error" }, `✗ ${panel.error}`) : null,
      el("h3", {}, "Addresses"),
      el("ul", { class: "plain" }, (panel.urls || []).map((u) => el("li", {}, el("code", {}, link(u.url, u.url)), el("span", { class: "muted" }, ` ${u.via}`)))),
      kv("Two-factor", [el("span", { class: factor.enabled ? "ok-text" : "warn-text" }, factor.enabled ? "on" : "off"), factor.required ? el("span", { class: "muted" }, " (required)") : null]),
      data.public_changes && !factor.enabled ? el("p", { class: "error" }, "Changes are allowed over the internet with the password alone. Turn two-factor login on.") : null,
      el("p", { class: "hint" }, "The password stays on the server: rift panel password.")),
    panelBox("Devices with panel access",
      (panel.devices || []).length ? el("ul", { class: "plain" }, panel.devices.map((d) => el("li", {}, dot(d.enabled ? "ok" : "off"), el("strong", {}, d.name), el("span", { class: "muted" }, ` ${d.ipv4}`))))
        : el("p", { class: "muted" }, "None. Grant one with g, or connect a new device on the VPN devices tab."),
      (panel.allow || []).length ? kv("Also allowed", panel.allow.join(", ")) : null));
}

function drawLogs() {
  const ws = words(state.logs.text);
  const lines = state.logs.lines
    .filter((l) => !ws.length || ws.every((w) => l.toLowerCase().includes(w)))
    .map((l) => logLine(l, true))
    .filter((l) => l.rank >= state.logs.level)
    .map((l) => l.node);
  const box = el("div", { class: "logs full" }, lines.length ? lines : el("p", { class: "muted" }, "No log entries (Docker keeps older ones: docker logs rift-server)."));
  if (state.logs.follow) requestAnimationFrame(() => { box.scrollTop = box.scrollHeight; });
  return panelBox(`Log · ${state.logs.follow ? "following" : "paused"}`, box);
}

function drawHealth() {
  if (!state.checks) return panelBox("Health", el("p", { class: "muted" }, "Running the checks…"));
  if (state.checks.error) return panelBox("Health", el("p", { class: "error" }, state.checks.error));
  const checks = state.checks.list;
  const items = attention();
  // What the overview lists counts too: a panel that does not run is no "everything fine".
  const failures = checks.filter((c) => c.status === "fail").length + items.filter((i) => i.className === "bad").length;
  const warnings = checks.filter((c) => c.status !== "fail" && c.status !== "ok").length + items.filter((i) => i.className === "warn").length;
  return [
    panelBox("Health",
      el("p", { class: failures ? "error" : warnings ? "warn-text" : "ok-text" },
        failures ? `✗ ${failures} problem(s) to fix.` : warnings ? `! ${warnings} warning(s); RIFT works, but see below.` : "✓ Everything looks fine."),
      checks.length ? null : el("p", { class: "muted" }, "The daemon reported no kernel checks."),
      el("table", { class: "checks" }, el("tbody", {}, checks.map((c) => el("tr", {},
        el("td", { class: c.status === "ok" ? "ok-text" : c.status === "fail" ? "error" : "warn-text" }, c.status === "ok" ? "✓" : c.status === "fail" ? "✗" : "!"),
        el("td", {}, el("strong", {}, c.check)),
        el("td", {}, c.detail)))))),
    items.length ? panelBox("Attention", el("ul", { class: "plain attention" }, items)) : null,
  ].filter(Boolean);
}

function drawBackup() {
  return el("div", { class: "two" },
    panelBox("Export and import",
      el("p", {}, "An ", el("strong", {}, "export"), " holds agent names, forwards, VPN devices with their grants, names and sites, but no keys. Import it here or on another server."),
      el("p", { class: "hint" }, "Import creates what this server lacks and leaves everything else alone; it shows what would happen first."),
      canWrite ? el("div", { class: "btns" }, button("Export settings", exportDialog, "primary"), button("Import settings", importDialog)) : null),
    panelBox("Backup",
      el("p", {}, "A ", el("strong", {}, "backup"), " holds everything with every key, to move or recover this server with ", el("code", {}, "sudo rift restore FILE"), "."),
      el("p", { class: "error" }, "Whoever has the file can pose as this server: keep it private and offline."),
      canWrite ? el("div", { class: "btns" }, button("Download backup", backupDialog, "danger")) : null));
}

function helpDialog() {
  const k = (key, text) => el("tr", {}, el("td", {}, el("kbd", {}, key)), el("td", {}, text));
  openModal("Keys",
    el("table", { class: "keys" }, el("tbody", {},
      k("1 … 9, 0", "switch tabs"),
      k("↑ ↓", "select a row"),
      k("Enter / right click", "the actions of the selected row"),
      k("letters", "the actions in the bar at the bottom"),
      k("/", "filter the list"),
      k("F", "focus on one agent"),
      k("R", "reconcile"),
      k("Esc", "close a dialog or menu"))),
    el("p", { class: "hint" }, "Forwards filter: a number matches the ID or a port (also inside a range); agent:NAME, port:N, proto:tcp and state:pending match one field. The same works in rift list forwards and the terminal UI (rift)."),
    el("div", { class: "form" }, el("div", { class: "buttons" }, button("Close", closeModal, "primary"))));
}

// ---------- loading ----------

async function load() {
  try {
    data = await api("/api/overview");
    sampleTraffic();
    if (!data.apply_error) showBanner("");
    else showBanner(`Last apply failed: ${data.apply_error}`);
    render();
  } catch (e) {
    if (e.message !== "session expired") showBanner(`Could not load: ${e.message}`);
  }
}

async function loadLogs() {
  try {
    const result = await act({ action: "logs", lines: 500 }, { quiet: true });
    state.logs.lines = result.lines || [];
    if (state.tab === "logs" || state.tab === "overview") render();
  } catch (_) { /* the overview shows the error */ }
}

async function loadChecks() {
  state.checks = null;
  if (state.tab === "health") render();
  try {
    const result = await act({ action: "diagnostics" }, { quiet: true });
    state.checks = { list: ((result.doctor || {}).checks) || [] };
  } catch (e) { state.checks = { error: e.message }; }
  if (state.tab === "health") render();
}

function schedule() {
  clearInterval(timer);
  clearInterval(logTimer);
  timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
  logTimer = setInterval(() => {
    if (!document.hidden && ((state.tab === "logs" && state.logs.follow) || state.tab === "overview")) loadLogs();
  }, LOG_REFRESH_MS);
}

// ---------- keys ----------

function onKey(event) {
  const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement && document.activeElement.tagName);
  if (event.key === "Escape") {
    if (!$("menu").hidden) { closeMenu(); return; }
    if (!$("modal").hidden) { closeModal(); return; }
    if (typing) { document.activeElement.blur(); return; }
  }
  if (!$("modal").hidden || !$("menu").hidden || typing || event.ctrlKey || event.metaKey || event.altKey) return;
  if ($("app").hidden) return;
  const key = event.key;
  if (/^[0-9]$/.test(key)) { switchTab(TABS[(Number(key) + 9) % 10].id); event.preventDefault(); return; }
  if (key === "/" ) { const f = $("filter"); if (f) { f.focus(); event.preventDefault(); } return; }
  if (key === "?") { helpDialog(); return; }
  if (key === "F") { focusMenu(null); return; }
  if (key === "R" && canWrite) { runAct({ action: "reload" }); return; }
  if (key === "ArrowDown" || key === "ArrowUp") {
    const tab = state.tab;
    if (!KEYS[tab]) return;
    const list = rows(tab);
    if (!list.length) return;
    const current = selected(tab);
    let i = list.indexOf(current);
    i = Math.max(0, Math.min(list.length - 1, i + (key === "ArrowDown" ? 1 : -1)));
    state.selected[tab] = KEYS[tab](list[i]);
    render();
    const row = $("view").querySelector("tr.selected");
    if (row) row.scrollIntoView({ block: "nearest" });
    event.preventDefault();
    return;
  }
  if (key === "Enter") {
    const list = actions();
    if (list.length) menuAt(null, list.map((a) => ({ label: a.label, hint: a.key, run: a.run, danger: a.danger })));
    return;
  }
  const action = actions().find((a) => a.key === key);
  if (action) { event.preventDefault(); action.run(); }
}

// ---------- dialogs and forms ----------

function closeModal() {
  $("modal").hidden = true;
  $("modal-body").replaceChildren();
}

function openModal(title, ...content) {
  $("modal-title").textContent = title;
  $("modal-body").replaceChildren(...content.filter(Boolean));
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

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type: type || "text/plain" }));
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

const CHECKOUT = "git clone https://github.com/weneten/RIFT.git\ncd RIFT";

// The invitation with what to copy: the whole setup, only the join line (for a host that has
// RIFT already), or the three .env lines of a manual setup.
function showInvitation(result) {
  const setup = `${CHECKOUT}
${result.join}`;
  openModal(`Invitation for ${result.name}`,
    el("p", { class: "hint" }, "Works once. The token is a secret; it is shown only now."),
    result.replaces ? el("p", { class: "notice" }, `${result.name} already exists: the install that uses this invitation takes over its key and keeps its addresses, forwards, grants and exits.`) : null,
    el("h4", {}, "On the agent host, with Docker installed"),
    el("pre", { class: "pre" }, setup),
    el("div", { class: "buttons" },
      button("Copy setup", (e) => copy(setup, e.currentTarget), "primary"),
      button("Copy join line only", (e) => copy(result.join, e.currentTarget))),
    el("h4", {}, "Or by hand: these lines in the agent's .env"),
    el("pre", { class: "pre" }, result.lines),
    el("div", { class: "buttons" }, button("Copy .env lines", (e) => copy(result.lines, e.currentTarget))),
    el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal))));
}

// `existing` re-invites an active agent: the new install takes over its key and settings.
function inviteDialog(existing) {
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "e.g. node2" });
  if (existing) Object.assign(name, { value: existing, readOnly: true });
  const ttl = select([["15m", "15 minutes"], ["30m", "30 minutes"], ["1h", "1 hour"], ["24h", "24 hours"]], "15m");
  openModal(existing ? `Invite ${existing} again` : "Invite agent", form([
    row("Agent name", name),
    row("Valid for", ttl),
    existing ? el("p", { class: "notice" }, `For a reinstalled ${existing}: the install that uses this invitation takes over its key and keeps its addresses, forwards, grants and exits. The old install stops working then.`) : null,
    el("p", { class: "hint" }, "The enrollment port opens now and closes again when the agent is active, the invitation expires or is cancelled."),
  ], "Create invitation", async () => {
    const result = await act({ action: "agent_invite", name: name.value.trim(), ttl: ttl.value });
    await load();
    showInvitation(result);
  }));
}

function forwardDialog(preset) {
  const agents = agentOptions(true);
  if (!agents.length) {
    showBanner("No active agent yet. Invite one first.");
    return;
  }
  const agent = select(agents, typeof preset === "string" ? preset : agents[0][0]);
  const specs = el("input", { required: true, placeholder: "e.g. 8080:80/tcp 53/both 5000-5002/udp" });
  const ips = data.public_ips || [];
  const hasV6 = ips.some((ip) => ip.includes(":"));
  const on = select([["v4", "IPv4"], ...(hasV6 ? [["v6", "IPv6"], ["all", "IPv4 and IPv6"]] : [])], "v4");
  const mode = select([["", "automatic"], ["transparent", "transparent (client IP visible)"], ["translate", "translate (IPv4 ↔ IPv6)"]], "");
  const ingress = select([["public", "public"], ["local", "local (for a proxy on this server)"]], "public");
  const allowFrom = el("input", { placeholder: "empty for everyone, or e.g. 203.0.113.7 198.51.100.0/24" });
  openModal("Add forwards", form([
    row("Agent", agent),
    row("Ports", specs),
    el("p", { class: "hint" }, "LISTEN[:TARGET]/tcp, /udp or /both, several separated by spaces. The target defaults to the listen port. A port may end in /v4, /v6 or /all to override the server address below."),
    el("div", { class: "row inline" }, row("Server address", on), row("Mode", mode)),
    row("Ingress", ingress),
    row("Only from", allowFrom),
    el("p", { class: "hint" }, "Leave empty for every client. Otherwise only these addresses or networks reach the service; everyone else sees a closed port. Not for local ingress."),
    el("p", { class: "hint" }, "Automatic is transparent: the service sees the client's address and must listen on the same IP version on the agent (0.0.0.0, or :: for IPv6). Translate bridges IPv6 clients to an IPv4-only service, but the service then sees the server instead of the client. Open the public ports in your cloud firewall as well."),
  ], "Add", async () => {
    const body = { action: "forward_add", agent: agent.value, specs: specs.value, on: on.value, ingress: ingress.value, allow_from: allowFrom.value };
    if (mode.value) body.mode = mode.value;
    const result = await act(body);
    closeModal();
    await load();
    if ((result.warnings || []).length) showBanner(result.warnings.join(" "));
  }));
}

function banDialog(forward) {
  const ip = el("input", { required: true, placeholder: "e.g. 198.51.100.23" });
  const ttl = select([["10m", "10 minutes"], ["1h", "1 hour"], ["6h", "6 hours"], ["24h", "24 hours"]], "1h");
  openModal(`Ban a client on forward ${forward.id}`, form([
    row("Client address", ip),
    row("Duration", ttl),
  ], "Ban", async () => {
    await act({ action: "ban_add", forward_id: forward.id, ip: ip.value.trim(), ttl: ttl.value });
    closeModal();
    await load();
  }));
}

// Turns names on or off (an agent's or a device's) and says which devices must import their
// main profile again, because their DNS server changed.
async function namesChange(body) {
  try {
    const result = await act(body, { quiet: true });
    await load();
    const devices = result.reimport || [];
    const lines = [body.action === "agent_names"
      ? (body.on ? `Devices with a grant now reach it as ${result.dns_name}.` : `${result.dns_name} no longer resolves.`)
      : (body.on ? `${body.name} uses RIFT's names.` : `${body.name} no longer uses RIFT's names.`)];
    lines.push(devices.length
      ? `The main profile of ${devices.join(", ")} changed (its DNS server): import it again on the device (Config button).`
      : "No device needs a new configuration.");
    openModal("Names", el("div", { class: "notice", role: "status" }, ...lines.map((t) => el("p", {}, t))),
      el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
  } catch (e) { showBanner(e.message); }
}

// Like `rift vpn connect`: the device (created if it does not exist), the ports it may reach
// on one agent, panel access if wanted, then its QR code with the addresses to open.
function deviceDialog() {
  const peers = data.vpn_peers || [];
  const list = el("datalist", { id: "device-names" }, ...peers.map((p) => el("option", { value: p.name })));
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "e.g. phone", list: "device-names" });
  const agents = agentOptions(true);
  const agent = select([["", "none"], ...agents], agents.length ? agents[0][0] : "");
  const ports = el("input", { placeholder: "e.g. 3000/tcp 8080/tcp" });
  const panel = el("input", { type: "checkbox" });
  openModal("Connect a VPN device", form([
    list,
    row("Device name (new or existing)", name),
    el("div", { class: "row inline" }, row("Agent", agent), row("Ports on the agent", ports)),
    check("May open this panel", panel),
    el("p", { class: "hint" }, "Only what you name here is reachable: no public port is opened. Leave the ports empty to create the device without access. More access and internet exits: the device's Access button."),
  ], "Connect", async () => {
    const device = name.value.trim();
    const wanted = ports.value.trim();
    if (wanted && !agent.value) throw new Error("Choose the agent the ports are on.");
    const existed = peers.some((p) => p.name === device);
    // The configuration routes addresses, not ports: compare it to say whether to re-import.
    let before = null;
    if (existed) {
      try { before = (await act({ action: "vpn_config", name: device })).config; } catch (_) { /* compared below */ }
    }
    if (!existed) await act({ action: "vpn_peer_add", name: device, panel: panel.checked }, { quiet: true });
    else if (panel.checked) await act({ action: "panel_allow", name: device, allowed: true }, { quiet: true });
    const notes = [];
    if (wanted) {
      const result = await act({ action: "vpn_allow", peer: device, agent: agent.value, ports: wanted }, { quiet: true });
      const refusals = result.warnings || [];
      notes.push(...refusals);
      const host = (data.agents || []).find((a) => a.name === agent.value);
      const ip = host && host.tunnel_ipv4;
      if (ip && refusals.length) {
        notes.push(`Stored, but not reachable yet: ${agent.value} refuses ${refusals.length === 1 ? "this grant" : "some of these grants"} (see above). It works once ${agent.value} allows it.`);
      } else if (ip) {
        for (const spec of wanted.split(/[\s,]+/).filter(Boolean)) {
          const [port, proto] = spec.split("/");
          notes.push(proto === "tcp" && /^\d+$/.test(port)
            ? `Once connected: ${ip}:${port}/tcp (if it serves a web page: http://${ip}:${port})`
            : `Once connected: ${ip}:${spec}`);
        }
      }
    }
    await load();
    if (existed && before !== null) {
      const after = (await act({ action: "vpn_config", name: device })).config;
      if (after === before) {
        notes.push(`${device}'s configuration is unchanged: the new access works on the device as it is, without importing anything.`);
        openModal(`Access of ${device}`, el("div", { class: "notice", role: "status" }, ...notes.map((t) => el("p", {}, t))),
          el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
        return;
      }
      notes.push(`${device}'s configuration changed: import this one on the device instead of the old one.`);
    }
    if (wanted || panel.checked) await configDialog(device, undefined, notes);
    else grantsDialog(device);
  }));
}

// The profiles of a device: the main one, then one per agent exit. Each is its own
// WireGuard configuration; the device uses the same keys and addresses in all of them.
async function configDialog(name, agent, notes) {
  const peer = (data.vpn_peers || []).find((p) => p.name === name);
  const agentExits = ((peer && peer.exits) || []).filter((x) => x.via === "agent" && x.agent).map((x) => x.agent);
  if (agent && !agentExits.includes(agent)) agent = undefined;
  let result;
  try {
    result = await act({ action: "vpn_config", name, ...(agent ? { agent } : {}) });
  } catch (e) {
    showBanner(`Configuration of ${name}: ${e.message}`);
    closeModal();
    return;
  }
  const profile = agent ? `extra profile via ${agent}` : "main profile";
  const image = el("img", { alt: `WireGuard QR code for ${name}, ${profile}`, src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(result.qr_svg)}` });
  const content = [];
  if (agentExits.length) {
    const choice = select([["", "Main profile"], ...agentExits.map((n) => [n, `Extra profile via ${n}`])], agent || "");
    choice.addEventListener("change", () => configDialog(name, choice.value || undefined, notes));
    content.push(row("Profile", choice));
  }
  if (notes && notes.length) content.push(el("div", { class: "notice", role: "status" }, ...notes.map((t) => el("p", {}, t))));
  openModal(`WireGuard configuration: ${name}`,
    ...content,
    el("p", { class: "warn-text" }, "Contains the device's private key. Do not share or store it carelessly."),
    el("div", { class: "qr" }, image),
    el("pre", { class: "pre" }, result.config),
    el("div", { class: "form" }, el("div", { class: "buttons" },
      button("Copy", (e) => copy(result.config, e.currentTarget)),
      button("Download .conf", () => download(agent ? `${name}-${agent}.conf` : `${name}.conf`, result.config)),
      button("Done", closeModal, "primary"))));
}

// Turning two-factor login on: scan the new secret, then prove it works with a code.
async function twoFactorDialog() {
  let result;
  try {
    result = await act({ action: "two_factor_setup" });
  } catch (e) {
    showBanner(`Two-factor setup: ${e.message}`);
    return;
  }
  const image = el("img", { alt: "Authenticator QR code", src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(result.qr_svg)}` });
  const code = el("input", { required: true, inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7", placeholder: "six digits" });
  openModal("Enable two-factor login",
    el("p", { class: "hint" }, "Scan the code with an authenticator app, or type the secret in. Then enter the current code to turn it on."),
    el("div", { class: "qr" }, image),
    el("pre", { class: "pre" }, result.secret),
    form([row("Code", code)], "Enable", async () => {
      await act({ action: "two_factor_confirm", code: code.value });
      closeModal();
      await load();
    }));
}

function twoFactorOffDialog() {
  const code = el("input", { required: true, inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7", placeholder: "six digits" });
  openModal("Disable two-factor login", form([
    row("Current code", code),
    el("p", { class: "hint" }, "All sessions end, including this one."),
  ], "Disable", async () => {
    await act({ action: "two_factor_disable", code: code.value });
    showLogin();
  }));
}

// Switches one exit of a device and says which profile to import again or delete in the
// WireGuard app. `exit` is "server" (the main profile) or { agent } (an extra profile).
async function changeExit(name, exit, on) {
  const result = await act({ action: "vpn_exit", peer: name, exit, on }, { quiet: true });
  await load();
  const notes = [];
  if (exit === "server") {
    notes.push(on
      ? "Main profile: it now sends all traffic through this server. Delete the old profile of this device in the WireGuard app and import the main profile again."
      : "Main profile: it no longer sends all traffic through this server. Delete the old profile of this device in the WireGuard app and import the main profile again.");
  } else if (on) {
    notes.push(`New extra profile via ${exit.agent}: import it in the WireGuard app with its QR code / config. The main profile stays as it is; switch between the profiles in the app.`);
  } else {
    notes.push(`Extra profile via ${exit.agent} removed: delete that profile in the WireGuard app. The main profile is unchanged.`);
  }
  if (on) {
    if (result.warning) notes.push(result.warning);
    if (result.waiting) notes.push(`Not ready yet: ${result.waiting}`);
    if (result.ipv6 === false) notes.push(`The profile has no IPv6: the device's IPv6 traffic is dropped, not leaked.`);
  }
  return notes;
}

// The DNS server of a device's main profile: the default, or an agent (for example an
// AdGuard at home), which also allows port 53 there.
function dnsRow(name, peer, agents, refresh) {
  const current = (peer.grants || []).find((g) => g.access === "dns");
  const choice = select([["default", "Default (none, or RIFT_VPN_DNS with the exit above)"],
    ...agents.map(([n]) => [n, `Agent ${n} (port 53 on its tunnel address)`])], current ? current.agent : "default");
  choice.addEventListener("change", async () => {
    choice.disabled = true;
    try {
      const result = await act({ action: "vpn_dns", peer: name, agent: choice.value === "default" ? null : choice.value }, { quiet: true });
      const notes = [(result.reimport || []).includes(name)
        ? `DNS of ${name} changed. Import the main profile again in the WireGuard app.`
        : `DNS of ${name} changed. RIFT passes the lookups on; the device's configuration stays as it is.`];
      if (result.warning) notes.push(result.warning);
      await refresh(notes);
    } catch (e) {
      choice.disabled = false;
      showBanner(`DNS of ${name}: ${e.message}`);
    }
  });
  return row("DNS server", choice);
}

// The note in a device's Access dialog after a change: import again, or nothing to do.
function importNote(name, result) {
  return (result && (result.reimport || []).includes(name))
    ? [`The configuration of ${name} changed: import it again on the device (QR code / config below).`]
    : [`The configuration of ${name} is unchanged: the change works without importing anything.`];
}

// How the VPS host resolves the agent's name (as names::host_name_note in the terminal UI):
// the host service reports its state in host_names.
function hostNameRow(a) {
  if (!(a.host_grants || []).length || !a.dns_name) return null;
  const host = data.host_names || {};
  const name = a.dns_name;
  let fine = false;
  let text;
  if (!a.names) text = `${name}: names off (n turns them on)`;
  else if (!host.state) text = `${name}: the host part is missing (sudo sh deploy/install-cli)`;
  else if (host.state === "off") text = `${name}: switched off on the VPS (sudo rift host names on)`;
  else if (host.state === "unavailable") text = `${name}: not possible here: ${host.detail}`;
  else if (host.state === "error") text = `${name}: ${host.detail}`;
  else if (!(host.domains || []).includes(name)) text = `${name}: being applied`;
  else if (host.lookup === "missing") text = `${name} resolves, but ssh does not ask systemd-resolved (apt install libnss-resolve)`;
  else { fine = true; text = `${name} ✓ (ssh USER@${name} on the VPS)`; }
  return kv("Name on the VPS", el("span", { class: fine ? "ok-text" : "warn-text" }, text));
}

// What the VPS host itself may reach on an agent (`rift host allow`): no public port, no device.
function hostDialog(name) {
  const agent = (data.agents || []).find((a) => a.name === name);
  if (!agent) { closeModal(); return; }
  const refresh = async () => { await load(); hostDialog(name); };
  const list = el("ul", { class: "grant-list" });
  for (const g of agent.host_grants || []) {
    list.append(el("li", {}, el("span", { title: g.refused || "" }, `${access(g.access)}${g.refused ? " (refused by the agent)" : ""}`),
      button("Withdraw", async () => {
        try {
          await act({ action: "host_deny", agent: name, access: g.access });
          await refresh();
        } catch (e) { showBanner(e.message); }
      }, "danger")));
  }
  if (!list.children.length) list.append(el("li", { class: "muted" }, "No access yet."));
  const content = [
    el("p", { class: "hint" }, `Lets the VPS host itself (its shell, programs with host networking) connect to ${agent.tunnel_ipv4 || "the agent's tunnel address"}, for example ssh USER@${agent.tunnel_ipv4 || "ADDRESS"} on the VPS. Nothing is published; Docker containers in bridge networks and VPN devices do not gain access. The agent's RIFT_AGENT_ALLOW_PORTS still applies.`),
    el("h4", {}, "Current access"), list];
  if (agent.status === "active") {
    const kind = select([["ports", "ports on the agent host"], ["server", "the agent host (TCP, UDP, ping)"], ["full", "the agent host, all protocols"]], "ports");
    const value = el("input", { placeholder: "e.g. 22/tcp 8000-8010/tcp" });
    const valueRow = row("Ports", value);
    const update = () => { valueRow.hidden = kind.value !== "ports"; value.required = !valueRow.hidden; };
    kind.addEventListener("change", update);
    update();
    content.push(el("hr", { class: "sep" }), el("h4", {}, "Allow more"), form([row("Access to", kind), valueRow], "Allow", async () => {
      const body = { action: "host_allow", agent: name };
      if (kind.value === "server") body.server = true;
      if (kind.value === "full") body.full = true;
      if (kind.value === "ports") body.ports = value.value;
      const result = await act(body);
      await refresh();
      if ((result.warnings || []).length) showBanner(result.warnings.join(" "));
    }));
  } else {
    content.push(el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
  }
  openModal(`Server access to ${name}`, ...content);
}

function grantsDialog(name, notes) {
  const peer = (data.vpn_peers || []).find((p) => p.name === name);
  if (!peer) { closeModal(); return; }
  const refresh = async (notes) => { await load(); grantsDialog(name, notes); };
  const list = el("ul", { class: "grant-list" });
  if (peer.panel) {
    list.append(el("li", {}, el("span", {}, "web panel"),
      button("Withdraw", async () => { const result = await act({ action: "panel_allow", name, allowed: false }); await refresh(importNote(name, result)); }, "danger")));
  }
  for (const g of peer.grants || []) {
    list.append(el("li", {}, el("span", { title: g.refused || "" }, `${g.agent || "?"}: ${access(g.access)}${g.refused ? " (refused by the agent)" : ""}`),
      button("Withdraw", async () => {
        try {
          const result = await act({ action: "vpn_deny", peer: name, agent: g.agent, access: g.access });
          await refresh(importNote(name, result));
        } catch (e) { showBanner(e.message); }
      }, "danger")));
  }
  for (const x of peer.exits || []) {
    list.append(el("li", {}, el("span", { title: x.reason || "" }, exitText(x)),
      button("Withdraw", async () => {
        try {
          const exit = x.via === "server" ? "server" : { agent: x.agent };
          refresh(await changeExit(name, exit, false));
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
      value.placeholder = kind.value === "ports" ? "e.g. 22/tcp 53/both" : "e.g. 192.168.178.0/24";
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
      const result = await act(body);
      await refresh(importNote(name, result));
      if ((result.warnings || []).length) showBanner(result.warnings.join(" "));
    }));
  }
  const exitOf = (agent) => (peer.exits || []).find((x) => agent ? x.via === "agent" && x.agent === agent : x.via === "server");
  const toggle = (label, current, exit, extra) => {
    const box = el("input", { type: "checkbox", checked: !!current });
    box.addEventListener("change", async () => {
      box.disabled = true;
      try {
        refresh(await changeExit(name, exit, box.checked));
      } catch (e) {
        box.checked = !box.checked;
        box.disabled = false;
        showBanner(`Exit of ${name}: ${e.message}`);
      }
    });
    return el("div", { class: "profile-row" }, check(label, box), extra);
  };
  const profileNames = [...new Set([...agents.map(([n]) => n),
    ...(peer.exits || []).filter((x) => x.via === "agent" && x.agent).map((x) => x.agent)])];
  content.push(el("hr", { class: "sep" }), el("h4", {}, "Exit (all traffic through RIFT)"),
    notes && notes.length ? el("div", { class: "notice", role: "status" }, ...notes.map((t) => el("p", {}, t))) : null,
    el("div", { class: "exit-block" },
      el("h5", {}, "Main profile (panel and grants)"),
      toggle("Send all traffic through this server", exitOf(), "server",
        button("QR code / config", () => configDialog(name))),
      el("p", { class: "hint" }, "The main profile is the only one that reaches the web panel and the grants above. Without this box it routes only what the grants name."),
      dnsRow(name, peer, agents, refresh)),
    el("div", { class: "exit-block" },
      el("h5", {}, "Extra profiles (one WireGuard entry each, all traffic through that home server)"),
      ...(profileNames.length ? profileNames.map((n) => {
        const x = exitOf(n);
        return toggle(`Profile via ${n}`, x, { agent: n }, x ? el("span", { class: "profile-extra" },
          button("QR code / config", () => configDialog(name, n)),
          x.state === "refused" ? el("span", { class: "error small", title: x.reason || "" }, ` refused by the agent${x.reason ? `: ${x.reason}` : ""}`)
            : x.state === "waiting" ? el("span", { class: "muted small" }, " waiting for the agent") : null) : null);
      }) : [el("p", { class: "muted" }, "No active agent yet.")]),
      el("p", { class: "hint" }, "Each extra profile is its own WireGuard entry with the same keys and addresses as the main one; switch between them in the WireGuard app. An agent must allow it with RIFT_AGENT_ALLOW_EXIT=true.")));
  const namesBox = el("input", { type: "checkbox", checked: !peer.names_off });
  namesBox.addEventListener("change", () => namesChange({ action: "vpn_peer_names", name, on: namesBox.checked }));
  content.push(el("hr", { class: "sep" }), el("h4", {}, "Names"),
    check(`Use RIFT's names (NAME.${data.names_suffix || "internal"}) for agents that have them on`, namesBox),
    el("p", { class: "hint" }, (peer.names || []).length
      ? `Resolves: ${peer.names.join(", ")}. While the tunnel is on, every lookup of the device goes through this server.`
      : "No agent this device reaches has names on. Turn them on per agent in the Agents card."));
  content.push(el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
  openModal(`Access of ${name}`, ...content);
}

// ---------- sites (carried out by the host service, see the README) ----------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const HOST_MISSING = "The host service did not pick up the request; is `rift-site-queue.path` installed and active? (sudo sh deploy/install-cli)";

// Waits up to 30 seconds for the host's answer to a queued request and shows it.
async function awaitSite(id, title) {
  const status = el("p", {}, "Waiting for the host service…");
  openModal(title, status, el("div", { class: "form" }, el("div", { class: "buttons" }, button("Close", closeModal))));
  const finish = (ok, text) => {
    if (!$("modal-body").contains(status)) return;
    openModal(title,
      el("p", { class: ok ? "" : "error", role: ok ? "status" : "alert" }, ok ? "Done." : "The host refused or failed:"),
      text ? el("pre", { class: "pre" }, text) : null,
      el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
  };
  for (let waited = 0; waited < 30000; waited += 1000) {
    await sleep(1000);
    if (!$("modal-body").contains(status)) { await load(); return; }
    let result;
    try {
      result = await act({ action: "site_result", id });
    } catch (e) {
      finish(false, e.message);
      return;
    }
    if (result.done) {
      await load();
      finish(result.ok, result.message);
      return;
    }
  }
  finish(false, HOST_MISSING);
}

function siteDialog() {
  const agents = agentOptions(true);
  if (!agents.length) {
    showBanner("No active agent yet. Invite one first.");
    return;
  }
  const agent = select(agents, agents[0][0]);
  const host = el("input", { required: true, placeholder: "e.g. app.example.net", maxlength: 253 });
  const port = el("input", { required: true, type: "number", min: 1, max: 65535, placeholder: "e.g. 8080" });
  const proxy = select([["", "default"], ["traefik", "Traefik"], ["caddy", "Caddy"], ["nginx", "Nginx"], ["npm", "Nginx Proxy Manager"]], "");
  const allowFrom = el("input", { placeholder: "empty for everyone, or e.g. 203.0.113.7 198.51.100.0/24" });
  openModal("Add site", form([
    row("Agent", agent),
    row("Domain", host),
    row("Target port on the agent", port),
    row("Proxy", proxy),
    row("Only from", allowFrom),
    el("p", { class: "hint" }, "Leave empty for every client. Otherwise the proxy answers everyone but these addresses or networks with 403."),
    el("p", { class: "hint" }, "The server's host service publishes https://DOMAIN through your reverse proxy to this port. The domain must already point at this server."),
  ], "Add site", async () => {
    const body = { action: "site_add", agent: agent.value, host: host.value.trim(), port: Number(port.value) };
    if (proxy.value) body.proxy = proxy.value;
    if (allowFrom.value.trim()) body.allow_from = allowFrom.value;
    const queued = await act(body);
    await awaitSite(queued.id, `Adding ${body.host}`);
  }));
}

// ---------- export, import and backup (run by the host service) ----------

function decodeBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Waits for the host's answer to a queued export, import or backup; returns it with its file.
async function awaitHostFile(id, status) {
  for (let waited = 0; waited < 120000; waited += 1000) {
    await sleep(1000);
    const result = await act({ action: "host_file", id }, { quiet: true });
    if (result.done) {
      if (!result.ok) throw new Error(result.message || "the host service failed");
      return result;
    }
    if (waited === 10000 && status) status.textContent = "Still waiting for the host service…";
  }
  throw new Error(HOST_MISSING);
}

function doneDialog(title, ...content) {
  openModal(title, ...content,
    el("div", { class: "form" }, el("div", { class: "buttons" }, button("Done", closeModal, "primary"))));
}

async function exportDialog() {
  const status = el("p", { role: "status" }, "Asking the host service…");
  openModal("Export settings", status);
  try {
    const queued = await act({ action: "export" });
    const result = await awaitHostFile(queued.id, status);
    download(result.file, decodeBase64(result.data), "application/json");
    doneDialog("Export settings",
      el("p", {}, `Saved ${result.file}.`),
      el("p", { class: "muted" }, result.message));
  } catch (e) {
    doneDialog("Export settings", el("p", { class: "error", role: "alert" }, e.message));
  }
}

const REPORT_GROUPS = [
  ["created", "Created", "Would create"],
  ["present", "Already present", "Already present"],
  ["skipped", "Skipped", "Skipped"],
  ["failed", "Failed", "Failed"],
];

function importReport(report) {
  const items = report.items || [];
  if (!items.length) return [el("p", {}, "Nothing to import.")];
  const out = [];
  for (const [status, title, dryTitle] of REPORT_GROUPS) {
    const group = items.filter((i) => i.status === status);
    if (!group.length) continue;
    out.push(el("h4", {}, `${report.dry_run ? dryTitle : title} (${group.length})`));
    out.push(el("ul", { class: "plain report" }, group.map((i) =>
      el("li", { class: status === "failed" ? "error" : "" }, i.detail ? `${i.what}: ${i.detail}` : i.what))));
  }
  return out;
}

async function runImport(document, map, dryRun, status) {
  const queued = await api("/api/import", { document, dry_run: dryRun, map });
  const result = await awaitHostFile(queued.id, status);
  return JSON.parse(new TextDecoder().decode(decodeBase64(result.data)));
}

function importDialog() {
  const file = el("input", { type: "file", accept: ".json,application/json", required: true });
  const map = el("input", { placeholder: "optional: node2=node1 node3=node1" });
  openModal("Import settings", form([
    row("Export file", file),
    row("Agent names", map),
    el("p", { class: "hint" }, "An import creates what this server lacks and leaves everything else alone. It never creates agents: invite them first. Map agents whose name differs here as OLD=NEW. You see what would happen before anything changes."),
  ], "Check", async () => {
    if (!file.files.length) throw new Error("choose an export file");
    let document;
    try {
      document = JSON.parse(await file.files[0].text());
    } catch (_) {
      throw new Error("this is not a RIFT export file (not JSON)");
    }
    const status = el("p", { role: "status" }, "Checking with the host service…");
    openModal("Import settings", status);
    let report;
    try {
      report = await runImport(document, map.value, true, status);
    } catch (e) {
      doneDialog("Import settings", el("p", { class: "error", role: "alert" }, e.message));
      return;
    }
    const creates = (report.items || []).some((i) => i.status === "created");
    openModal("Import settings",
      el("p", {}, "Nothing has changed yet."),
      ...importReport(report),
      el("div", { class: "form" }, el("div", { class: "buttons" },
        button(creates ? "Cancel" : "Close", closeModal),
        creates ? button("Import", async () => {
          const running = el("p", { role: "status" }, "Importing…");
          openModal("Import settings", running);
          try {
            const done = await runImport(document, map.value, false, running);
            await load();
            doneDialog("Import settings", ...importReport(done));
          } catch (e) {
            doneDialog("Import settings", el("p", { class: "error", role: "alert" }, e.message));
          }
        }, "primary") : null)));
  }));
}

function backupDialog() {
  const password = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const factor = (data && data.two_factor) || {};
  const code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: !!factor.enabled });
  openModal("Download backup", form([
    el("p", { class: "error" }, "The backup holds every key of this server: WireGuard, the enrollment CA, the VPN devices and the panel password. Whoever has the file can pose as this server."),
    el("p", { class: "hint" }, "Keep it private and offline, not only on this server. Restore it on a server with sudo rift restore FILE."),
    row("Panel password", password),
    factor.enabled ? row("Code", code) : null,
    factor.enabled ? el("p", { class: "hint" }, "A code works once. If you just logged in with the current code, wait for the next one.") : null,
  ].filter(Boolean), "Download backup", async () => {
    const body = { action: "backup", password: password.value };
    if (factor.enabled) body.code = code.value.trim();
    const queued = await act(body);
    password.value = "";
    const status = el("p", { role: "status" }, "The host service is writing the backup…");
    openModal("Download backup", status);
    try {
      const result = await awaitHostFile(queued.id, status);
      download(result.file, decodeBase64(result.data), "application/gzip");
      doneDialog("Download backup",
        el("p", {}, `Saved ${result.file}.`),
        el("p", { class: "error" }, "Keep it private: it holds every key of this server."));
    } catch (e) {
      doneDialog("Download backup", el("p", { class: "error", role: "alert" }, e.message));
    }
  }));
}


// ---------- login and start ----------

// The code field is only there while the server asks for a code.
async function updateLoginForm() {
  try {
    const session = await api("/api/session");
    $("code-row").hidden = !session.two_factor;
    $("code").required = !!session.two_factor;
    const refused = session.login_allowed === false;
    $("https-only").hidden = !refused;
    $("password").disabled = refused;
    $("login-form").querySelector("button[type=submit]").disabled = refused;
  } catch (_) { /* keep the form as it is */ }
}

function showLogin() {
  clearInterval(timer);
  clearInterval(logTimer);
  closeModal();
  closeMenu();
  $("app").hidden = true;
  $("login").hidden = false;
  $("code").value = "";
  updateLoginForm();
  $("password").focus();
}

async function showApp() {
  $("login").hidden = true;
  $("app").hidden = false;
  const wanted = location.hash.slice(1);
  if (TABS.some((t) => t.id === wanted)) state.tab = wanted;
  await load();
  switchTab(state.tab);
  schedule();
}

document.addEventListener("DOMContentLoaded", async () => {
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter || event.target.querySelector("button");
    submit.disabled = true;
    $("login-error").textContent = "";
    try {
      const body = { password: $("password").value };
      if (!$("code-row").hidden) body.code = $("code").value;
      await api("/api/login", body);
      $("password").value = "";
      $("code").value = "";
      await showApp();
    } catch (e) {
      $("login-error").textContent = e.message;
    } finally {
      submit.disabled = false;
    }
  });
  $("logout").addEventListener("click", async () => {
    try { await api("/api/logout", {}); } catch (_) { /* already gone */ }
    showLogin();
  });
  $("reload").addEventListener("click", () => runAct({ action: "reload" }));
  $("modal-close").addEventListener("click", closeModal);
  $("modal").addEventListener("click", (event) => { if (event.target === $("modal")) closeModal(); });
  document.addEventListener("click", (event) => { if (!$("menu").hidden && !$("menu").contains(event.target)) closeMenu(); });
  document.addEventListener("keydown", onKey);
  window.addEventListener("hashchange", () => switchTab(location.hash.slice(1)));
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("app").hidden) load(); });
  try {
    const session = await api("/api/session");
    if (session.authenticated) await showApp(); else showLogin();
  } catch (_) {
    showLogin();
  }
});
