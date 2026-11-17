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

// `existing` re-invites an active agent: the new install takes over its key and settings.
function inviteDialog(existing) {
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "node2" });
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
    openModal(`Invitation for ${result.name}`,
      el("p", { class: "hint" }, "Run this on the agent, in a RIFT checkout (git clone https://github.com/weneten/RIFT.git && cd RIFT). It prepares the host, starts the agent and removes the token once the agent is active. The token is a secret and works once."),
      result.replaces ? el("p", { class: "hint" }, `${result.name} keeps its addresses, forwards, grants and exits.`) : null,
      el("pre", { class: "pre" }, result.join),
      el("div", { class: "buttons" }, button("Copy command", (e) => copy(result.join, e.currentTarget), "primary")),
      el("p", { class: "hint" }, "Or put these three lines into the agent's .env yourself, then start it:"),
      el("pre", { class: "pre" }, result.lines),
      el("div", { class: "form" }, el("div", { class: "buttons" }, button("Copy lines", (e) => copy(result.lines, e.currentTarget)), button("Done", closeModal))));
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
  const ips = data.public_ips || [];
  const hasV6 = ips.some((ip) => ip.includes(":"));
  const on = select([["v4", "IPv4"], ...(hasV6 ? [["v6", "IPv6"], ["all", "IPv4 and IPv6"]] : [])], "v4");
  const mode = select([["", "automatic"], ["transparent", "transparent (client IP visible)"], ["translate", "translate (IPv4 ↔ IPv6)"]], "");
  const ingress = select([["public", "public"], ["local", "local (for a proxy on this server)"]], "public");
  const allowFrom = el("input", { placeholder: "everyone, or 203.0.113.7 198.51.100.0/24" });
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
  const ip = el("input", { required: true, placeholder: "198.51.100.23" });
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
    const result = await act(body);
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
  const name = el("input", { required: true, pattern: "[A-Za-z0-9_\\-]{1,63}", placeholder: "phone", list: "device-names" });
  const agents = agentOptions(true);
  const agent = select([["", "none"], ...agents], agents.length ? agents[0][0] : "");
  const ports = el("input", { placeholder: "3000/tcp 8080/tcp" });
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
    if (!existed) await act({ action: "vpn_peer_add", name: device, panel: panel.checked });
    else if (panel.checked) await act({ action: "panel_allow", name: device, allowed: true });
    const notes = [];
    if (wanted) {
      const result = await act({ action: "vpn_allow", peer: device, agent: agent.value, ports: wanted });
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
  const code = el("input", { required: true, inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7", placeholder: "123456" });
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
  const code = el("input", { required: true, inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7", placeholder: "123456" });
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
  const result = await act({ action: "vpn_exit", peer: name, exit, on });
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
      await act({ action: "vpn_dns", peer: name, agent: choice.value === "default" ? null : choice.value });
      await refresh([`DNS of ${name} changed. Import the main profile again in the WireGuard app.`]);
    } catch (e) {
      choice.disabled = false;
      showBanner(`DNS of ${name}: ${e.message}`);
    }
  });
  return row("DNS server", choice);
}

function grantsDialog(name, notes) {
  const peer = (data.vpn_peers || []).find((p) => p.name === name);
  if (!peer) { closeModal(); return; }
  const refresh = async (notes) => { await load(); grantsDialog(name, notes); };
  const list = el("ul", { class: "grant-list" });
  if (peer.panel) {
    list.append(el("li", {}, el("span", {}, "web panel"),
      button("Withdraw", async () => { await act({ action: "panel_allow", name, allowed: false }); await refresh(); }, "danger")));
  }
  for (const g of peer.grants || []) {
    list.append(el("li", {}, el("span", { title: g.refused || "" }, `${g.agent || "?"}: ${access(g.access)}${g.refused ? " (refused by the agent)" : ""}`),
      button("Withdraw", async () => {
        try {
          await act({ action: "vpn_deny", peer: name, agent: g.agent, access: g.access });
          await refresh();
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
      const result = await act(body);
      await refresh();
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
    check("Use RIFT's names (NAME.internal) for agents that have them on", namesBox),
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
  const host = el("input", { required: true, placeholder: "app.example.net", maxlength: 253 });
  const port = el("input", { required: true, type: "number", min: 1, max: 65535, placeholder: "8080" });
  const proxy = select([["", "default"], ["traefik", "Traefik"], ["caddy", "Caddy"], ["nginx", "Nginx"], ["npm", "Nginx Proxy Manager"]], "");
  const allowFrom = el("input", { placeholder: "everyone, or 203.0.113.7 198.51.100.0/24" });
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
        a.status === "active" ? button("Re-invite", () => inviteDialog(a.name)) : null,
        a.dns_name ? button(a.names ? "Names off" : "Names on", () => namesChange({ action: "agent_names", name: a.id, on: !a.names })) : null,
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
      el("td", {}, a.names && a.dns_name ? el("code", {}, a.dns_name) : el("span", { class: "muted" }, "off")),
      el("td", {}, a.status === "active" ? ago(a.last_handshake, now) : "-"),
      el("td", { class: "actions" }, actions));
  }), 7, invites.length ? "No agent has enrolled yet." : "No agents yet.");

  fill($("forwards"), forwards.map((f) => {
    const statePill = !f.enabled ? pill("disabled", "off")
      : f.refused ? Object.assign(pill("refused", "bad"), { title: f.refused })
      : f.pending ? pill("pending", "warn") : pill("active", "ok");
    const isExit = f.purpose === "exit";
    const only = (f.allow_from || []).length ? `only ${f.allow_from.join(", ")}` : null;
    const mode = [isExit ? "exit" : null, f.mode, f.ingress === "local" ? "local" : null, f.target_family, only].filter(Boolean).join(" · ");
    const listen = endpoint(f.listen_ip, range(f.listen_ports));
    const url = forwardUrl(f);
    return el("tr", {},
      el("td", {}, f.id),
      el("td", {}, f.agent),
      el("td", {}, String(f.protocol || "").toUpperCase()),
      el("td", {}, el("code", {}, url ? link(url, listen) : listen)),
      el("td", {}, range(f.target_ports)),
      el("td", { class: "muted" }, mode),
      el("td", {}, statePill),
      el("td", { class: "actions" }, isExit ? el("span", { class: "muted small" }, "managed by RIFT") : btns(
        f.mode === "translate" ? button("Ban", () => banDialog(f)) : null,
        f.enabled
          ? actionButton("Disable", { action: "forward_enable", id: f.id, enabled: false })
          : actionButton("Enable", { action: "forward_enable", id: f.id, enabled: true }),
        actionButton("Remove", { action: "forward_remove", id: f.id },
          `Remove forward ${f.id} (${endpoint(f.listen_ip, range(f.listen_ports))})? This cannot be undone.`, "danger"))));
  }), 8, "No forwards configured.");

  $("refused").replaceChildren(...forwards.filter((f) => f.refused && f.enabled).map((f) =>
    el("li", {}, el("strong", {}, `Forward ${f.id}`), ` refused by ${f.agent}: ${f.refused}`)));
  const bans = data.bans || [];
  $("bans-card").hidden = !bans.length;
  fill($("bans"), bans.map((b) => el("tr", {},
    el("td", {}, b.forward_id), el("td", {}, b.agent), el("td", {}, el("code", {}, b.ip)),
    el("td", {}, `in ${left(b.expires_at, now)}`))), 4, "");

  fill($("vpn"), peers.map((p) => {
    const grants = (p.grants || []).map((g) => `${g.agent || "?"}: ${access(g.access)}${g.refused ? " (refused)" : ""}`);
    if (p.panel) grants.unshift("panel");
    const exits = exitSummary(p);
    if (exits) grants.push(exits);
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

  const sites = data.sites || {};
  $("sites-hint").hidden = !!sites.available;
  fill($("sites"), (sites.sites || []).map((site) => {
    const statePill = site.forward === "ok" ? pill("ok", "ok")
      : site.forward === "refused" ? Object.assign(pill("refused", "bad"), { title: site.reason || "" })
      : pill("missing", "warn");
    return el("tr", {},
      el("td", {}, link(`https://${site.host}`, site.host)),
      el("td", {}, site.agent),
      el("td", {}, site.target),
      el("td", {}, site.proxy, (site.allow_from || []).length
        ? el("span", { class: "muted small" }, ` · only ${site.allow_from.join(", ")}`) : null),
      el("td", {}, statePill, site.forward_id ? el("span", { class: "muted small" }, ` #${site.forward_id}`) : null),
      el("td", { class: "actions" }, btns(button("Remove", async () => {
        if (!window.confirm(`Remove the site ${site.host} and its forward?`)) return;
        try {
          const queued = await act({ action: "site_remove", host: site.host });
          await awaitSite(queued.id, `Removing ${site.host}`);
        } catch (e) { showBanner(`Action failed: ${e.message}`); }
      }, "danger"))));
  }), 6, sites.available ? "No sites." : "");

  const urls = $("panel-urls");
  urls.replaceChildren();
  for (const u of panel.urls || []) {
    urls.append(el("li", {}, el("code", {}, link(u.url, u.url)), el("span", { class: "muted" }, u.via)));
  }
  const devices = (panel.devices || []).map((d) => d.name);
  urls.append(el("li", {}, el("span", { class: "muted" }, "Devices with panel access:"), devices.length ? devices.join(", ") : "none"));
  if ((panel.allow || []).length) {
    urls.append(el("li", {}, el("span", { class: "muted" }, "Allowed addresses:"), panel.allow.join(", ")));
  }

  const factor = data.two_factor || {};
  $("add-site").onclick = siteDialog;
  $("two-factor").replaceChildren(...[
    el("span", { class: "muted" }, "Two-factor login: "),
    factor.enabled ? pill("on", "ok") : pill("off", "off"),
    factor.required ? el("span", { class: "muted small" }, factor.enabled ? " required by the server" : " required; set it up on the server with rift panel 2fa setup") : null,
    canWrite && !factor.required ? " " : null,
    canWrite && !factor.required ? (factor.enabled ? button("Disable", twoFactorOffDialog, "danger") : button("Enable", twoFactorDialog)) : null,
  ].filter(Boolean));

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

// The code field is only there while the server asks for a code.
async function updateLoginForm() {
  try {
    const session = await api("/api/session");
    $("code-row").hidden = !session.two_factor;
    $("code").required = !!session.two_factor;
  } catch (_) { /* keep the form as it is */ }
}

function showLogin() {
  clearInterval(timer);
  closeModal();
  $("app").hidden = true;
  $("login").hidden = false;
  $("code").value = "";
  updateLoginForm();
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
  $("refresh").addEventListener("click", load);
  $("reload").addEventListener("click", async () => {
    try { await act({ action: "reload" }); await load(); } catch (e) { showBanner(`Reconcile failed: ${e.message}`); }
  });
  $("add-agent").addEventListener("click", () => inviteDialog());
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
