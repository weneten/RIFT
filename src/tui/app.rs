//! State and behaviour of the terminal UI. Everything it changes goes through the same admin
//! requests as the CLI (and the web panel); sites go through the web panel's host queue.

use super::form::{Field, Form, Outcome};
use crate::{
    config::{validate_name, Config},
    model::*,
    output,
    protocol::AdminRequest,
    sites, vpn, webpanel,
};
use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::{
    layout::{Position, Rect},
    text::Line,
    widgets::TableState,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;

/// How often the overview is fetched again, and the log more often while it is shown.
const REFRESH: Duration = Duration::from_secs(3);
const LOG_REFRESH: Duration = Duration::from_secs(1);
/// Samples kept for the traffic graph.
const HISTORY: usize = 120;
/// How long a site request may wait for the host service.
const SITE_WAIT: Duration = Duration::from_secs(30);
/// How long a picked-up request (an import or backup can be slow) may take.
const SITE_RUN: Duration = Duration::from_secs(180);
const HOST_MISSING: &str = "The host service did not pick up the request; is rift-site-queue.path installed and active? (sudo sh deploy/install-cli)";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Server,
    Agent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tab {
    Overview,
    Agents,
    Forwards,
    Devices,
    Sites,
    Bans,
    Panel,
    Logs,
    Health,
    Backup,
}
impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Agents => "Agents",
            Self::Forwards => "Forwards",
            Self::Devices => "VPN devices",
            Self::Sites => "Sites",
            Self::Bans => "Bans",
            Self::Panel => "Web panel",
            Self::Logs => "Logs",
            Self::Health => "Health",
            Self::Backup => "Backup",
        }
    }
    /// The title on narrow windows.
    pub fn short(self) -> &'static str {
        match self {
            Self::Overview => "Home",
            Self::Devices => "Devices",
            Self::Panel => "Panel",
            other => other.title(),
        }
    }
    fn of(role: Role) -> Vec<Tab> {
        match role {
            Role::Server => vec![
                Self::Overview,
                Self::Agents,
                Self::Forwards,
                Self::Devices,
                Self::Sites,
                Self::Bans,
                Self::Panel,
                Self::Logs,
                Self::Health,
                Self::Backup,
            ],
            Role::Agent => vec![Self::Overview, Self::Forwards, Self::Logs, Self::Health],
        }
    }
}

/// Everything the UI shows, fetched together.
pub struct Snapshot {
    /// The admin `Status` answer.
    pub status: Value,
    /// Server: the web panel's overview (agents with health, forwards with states, devices,
    /// bans, invitations, panel, sites, two-factor state). Agent: `{"forwards": [...]}`.
    pub overview: Value,
    pub logs: Vec<String>,
}

pub enum Msg {
    Event(Event),
    Data(Box<Result<Snapshot, String>>),
    Logs(Vec<String>),
    Done {
        form: bool,
        result: Result<Done, String>,
    },
    Health(Result<Value, String>),
    Command {
        line: String,
        result: Result<std::process::Output, String>,
    },
}

/// What a finished operation shows.
pub enum Done {
    Message { text: String, warn: bool },
    Modal(Box<Modal>),
    Site { id: String, title: String },
    Password(String),
}

impl Done {
    fn modal(modal: Modal) -> Self {
        Self::Modal(Box::new(modal))
    }
}

/// Something that changes the server or reads a secret, run in the background.
pub enum Op {
    /// Admin requests in order; the first failure stops the rest.
    Requests(Vec<AdminRequest>),
    /// `replace`: withdraw the open invitation of that name first (a new token).
    Invite {
        name: String,
        ttl_seconds: u64,
        replace: bool,
    },
    Config {
        name: String,
        agent: Option<String>,
    },
    TwoFactorSetup,
    Password,
    Details(AdminRequest),
    Site {
        request: sites::Request,
        title: String,
    },
}

/// What a form does when it is submitted.
#[derive(Clone, Debug)]
pub enum Submit {
    Invite,
    Rename(String),
    Forward,
    Ban,
    Device,
    Grant(String),
    Site,
    TwoFactorConfirm,
    LogFilter,
    Import,
    ForwardFilter,
    Filter(Tab),
}

/// Actions on the current tab, reachable by key, footer button and the Enter/right-click menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    Invite,
    AgentToggle,
    AgentRename,
    AgentRotate,
    AgentNames,
    AgentForward,
    AgentDetails,
    CancelInvite,
    NewToken,
    AgentRemove,
    ForwardAdd,
    ForwardToggle,
    ForwardBan,
    ForwardRemove,
    DeviceAdd,
    DeviceGrant,
    DeviceDeny,
    DeviceConfig,
    DeviceExits,
    DeviceDns,
    DeviceNames,
    DevicePanel,
    DeviceToggle,
    DeviceRemove,
    SiteAdd,
    SiteRemove,
    BanAdd,
    Password,
    TwoFactorSetup,
    TwoFactorConfirm,
    TwoFactorReset,
    PanelGrant,
    PanelWithdraw,
    LogFollow,
    LogFilter,
    LogLevel,
    ForwardFilter,
    ForwardSort,
    /// The word filter of the current tab (agents, devices, sites, bans).
    Filter,
    Focus,
    HealthRun,
    Export,
    Backup,
    Import,
    Reconcile,
    Refresh,
    Command,
    Help,
    Quit,
}

pub enum MenuWhat {
    Act(Act),
    Op(Box<Op>),
    /// Shown but not selectable, e.g. an exit an agent refuses.
    Disabled,
    /// Show only this agent's rows (None: every agent).
    Focus(Option<String>),
}
impl MenuWhat {
    fn op(op: Op) -> Self {
        Self::Op(Box::new(op))
    }
}
pub struct MenuItem {
    pub label: String,
    pub hint: String,
    pub what: MenuWhat,
}

pub enum Modal {
    Form {
        form: Form,
        submit: Submit,
    },
    Confirm {
        title: String,
        text: String,
        op: Op,
        danger: bool,
        yes: bool,
    },
    Menu {
        title: String,
        items: Vec<MenuItem>,
        index: usize,
    },
    Text {
        title: String,
        lines: Vec<Line<'static>>,
        scroll: u16,
        /// What the copy buttons (keys 1, 2, … and y for the first) put on the clipboard.
        copy: Vec<Copyable>,
    },
    Qr {
        title: String,
        qr: String,
        text: String,
        note: String,
        show_text: bool,
        scroll: u16,
    },
    Site {
        title: String,
        id: String,
        started: Instant,
        result: Option<(bool, String)>,
        scroll: u16,
    },
    Help {
        scroll: u16,
    },
}

/// One text a dialog offers to copy (OSC 52), with its button label.
pub struct Copyable {
    pub label: &'static str,
    /// Says what was copied, after "Copied ".
    pub what: &'static str,
    pub text: String,
}

/// What a mouse click hit, recorded while drawing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    Tab(usize),
    Row(Tab, usize),
    Act(Act),
    /// The footer's "⏎ Menu" button: the actions of the selected row.
    Menu,
    /// The area of the open modal; clicks elsewhere close menus and texts.
    ModalArea,
    MenuItem(usize),
    Yes,
    No,
    Close,
    /// Copy button `n` of a text dialog; 0 also copies a QR dialog's text.
    Copy(usize),
    QrToggle,
    LogScroll,
}

pub struct Toast {
    pub text: String,
    pub level: Level,
    pub at: Instant,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

pub struct CommandLine {
    pub input: String,
    pub cursor: usize,
    /// Position in the history while browsing it with ↑/↓.
    pub back: Option<usize>,
}

pub struct LogView {
    /// Lines scrolled up from the newest one.
    pub scroll: usize,
    pub follow: bool,
    pub filter: String,
    /// 0 all, 1 info and above, 2 warnings and errors, 3 errors only.
    pub level: u8,
}

#[derive(Default)]
pub struct Traffic {
    previous: HashMap<String, (u64, u64)>,
    at: Option<Instant>,
    pub rx: VecDeque<u64>,
    pub tx: VecDeque<u64>,
    /// Bytes per second by WireGuard public key.
    pub rates: HashMap<String, (u64, u64)>,
}
impl Traffic {
    fn sample(&mut self, peers: &Value) {
        let now = Instant::now();
        let elapsed = self
            .at
            .map(|at| now.duration_since(at).as_secs_f64())
            .filter(|s| *s > 0.2);
        let mut rx_total = 0;
        let mut tx_total = 0;
        let mut seen = HashMap::new();
        for peer in peers.as_array().into_iter().flatten() {
            let key = peer["public_key"].as_str().unwrap_or_default().to_string();
            let rx = peer["rx_bytes"].as_u64().unwrap_or(0);
            let tx = peer["tx_bytes"].as_u64().unwrap_or(0);
            if let (Some(seconds), Some((prx, ptx))) = (elapsed, self.previous.get(&key)) {
                let r = (rx.saturating_sub(*prx) as f64 / seconds) as u64;
                let t = (tx.saturating_sub(*ptx) as f64 / seconds) as u64;
                self.rates.insert(key.clone(), (r, t));
                rx_total += r;
                tx_total += t;
            }
            seen.insert(key, (rx, tx));
        }
        if elapsed.is_some() {
            for (list, value) in [(&mut self.rx, rx_total), (&mut self.tx, tx_total)] {
                list.push_back(value);
                while list.len() > HISTORY {
                    list.pop_front();
                }
            }
        }
        self.rates.retain(|k, _| seen.contains_key(k));
        self.previous = seen;
        self.at = Some(now);
    }
}

pub struct App {
    pub config: Config,
    pub config_path: PathBuf,
    pub role: Role,
    pub tabs: Vec<Tab>,
    pub tab: usize,
    pub tables: HashMap<Tab, TableState>,
    pub snapshot: Option<Snapshot>,
    pub fetch_error: Option<String>,
    loading: bool,
    logs_loading: bool,
    last_fetch: Option<Instant>,
    last_logs: Option<Instant>,
    pub traffic: Traffic,
    pub modals: Vec<Modal>,
    pub toast: Option<Toast>,
    pub hits: Vec<(Rect, Hit)>,
    pub command: Option<CommandLine>,
    history: Vec<String>,
    pub logs: LogView,
    pub health: Option<Result<Value, String>>,
    pub health_loading: bool,
    pub busy: usize,
    pub password: Option<String>,
    /// Filter words and order of the Forwards tab (`crate::query`).
    pub forward_filter: String,
    pub forward_query: crate::query::ForwardQuery,
    /// Word filters of the Agents, VPN devices, Sites and Bans tabs.
    pub filters: HashMap<Tab, String>,
    /// The agent whose forwards, devices, sites and bans alone are shown (F).
    pub focus: Option<String>,
    pub quit: bool,
    pub frame: usize,
    tx: UnboundedSender<Msg>,
    last_click: Option<(Instant, Hit)>,
}

impl App {
    pub fn new(config: Config, config_path: PathBuf, tx: UnboundedSender<Msg>) -> Self {
        let role = if config.public_ips.is_empty() && config.public_endpoint.is_empty() {
            Role::Agent
        } else {
            Role::Server
        };
        Self {
            config,
            config_path,
            role,
            tabs: Tab::of(role),
            tab: 0,
            tables: HashMap::new(),
            snapshot: None,
            fetch_error: None,
            loading: false,
            logs_loading: false,
            last_fetch: None,
            last_logs: None,
            traffic: Traffic::default(),
            modals: Vec::new(),
            toast: None,
            hits: Vec::new(),
            command: None,
            history: Vec::new(),
            logs: LogView {
                scroll: 0,
                follow: true,
                filter: String::new(),
                level: 0,
            },
            health: None,
            health_loading: false,
            busy: 0,
            password: None,
            forward_filter: String::new(),
            forward_query: crate::query::ForwardQuery::default(),
            filters: HashMap::new(),
            focus: None,
            quit: false,
            frame: 0,
            tx,
            last_click: None,
        }
    }

    pub fn current(&self) -> Tab {
        self.tabs[self.tab]
    }
    pub fn overview(&self) -> &Value {
        static NULL: Value = Value::Null;
        self.snapshot.as_ref().map_or(&NULL, |s| &s.overview)
    }
    pub fn status(&self) -> &Value {
        static NULL: Value = Value::Null;
        self.snapshot.as_ref().map_or(&NULL, |s| &s.status)
    }

    /// The rows of a table tab.
    pub fn items(&self, tab: Tab) -> Vec<Value> {
        let mut items = self.unfiltered(tab);
        // The agent in focus (F): only what concerns it.
        if let Some(agent) = &self.focus {
            let named = |v: &Value| {
                v["agent"]
                    .as_str()
                    .is_some_and(|a| a.eq_ignore_ascii_case(agent))
            };
            match tab {
                Tab::Forwards | Tab::Sites | Tab::Bans => items.retain(named),
                Tab::Devices => items.retain(|d| crate::query::device_uses(d, agent)),
                _ => {}
            }
        }
        if let Some(words) = self.filters.get(&tab) {
            let words = crate::query::words(words);
            items.retain(|item| crate::query::matches_words(item, &words));
        }
        items
    }

    /// The rows of a tab before the focus and the word filter.
    pub fn unfiltered(&self, tab: Tab) -> Vec<Value> {
        let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
        match tab {
            Tab::Agents => {
                // Agents exist only once enrolled; an open invitation of a new name is a row
                // of its own until then.
                let mut agents = list(&self.overview()["agents"]);
                for invite in self.overview()["invites"].as_array().into_iter().flatten() {
                    let name = &invite["name"];
                    if !agents.iter().any(|a| a["name"] == *name) {
                        agents.push(json!({
                            "name": name,
                            "status": "invited",
                            "invite": true,
                            "expires_at": invite["expires_at"],
                        }));
                    }
                }
                agents
            }
            Tab::Forwards => {
                let agent_role = self.role == Role::Agent;
                self.forward_query.apply(&self.all_forwards(), |f| {
                    if agent_role {
                        String::new()
                    } else {
                        f["agent"].as_str().unwrap_or_default().to_string()
                    }
                })
            }
            Tab::Devices => list(&self.overview()["vpn_peers"]),
            Tab::Sites => list(&self.overview()["sites"]["sites"]),
            Tab::Bans => list(&self.overview()["bans"]),
            Tab::Backup => list(&self.overview()["files"]),
            Tab::Health => match &self.health {
                Some(Ok(data)) => list(&data["checks"]),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
    /// Every forward, whatever the Forwards tab's filter shows.
    pub fn all_forwards(&self) -> Vec<Value> {
        self.overview()["forwards"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    pub fn table(&mut self, tab: Tab) -> &mut TableState {
        self.tables.entry(tab).or_default()
    }
    pub fn selected(&self) -> Option<Value> {
        let tab = self.current();
        let index = self.tables.get(&tab).and_then(TableState::selected)?;
        self.items(tab).into_iter().nth(index)
    }
    /// Keeps each table's selection inside its rows.
    fn clamp_selections(&mut self) {
        for tab in self.tabs.clone() {
            let len = self.items(tab).len();
            let state = self.table(tab);
            match (state.selected(), len) {
                (_, 0) => state.select(None),
                (None, _) => state.select(Some(0)),
                (Some(i), n) if i >= n => state.select(Some(n - 1)),
                _ => {}
            }
        }
    }

    fn agent_names(&self, active_only: bool) -> Vec<String> {
        self.unfiltered(Tab::Agents)
            .iter()
            .filter(|a| !active_only || a["status"] == "active")
            .filter_map(|a| a["name"].as_str().map(String::from))
            .collect()
    }
    /// The open invitation for an agent name: seconds until it expires.
    pub fn invite_left(&self, name: &str) -> Option<i64> {
        self.overview()["invites"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|i| i["name"].as_str() == Some(name))
            .map(|i| i["expires_at"].as_i64().unwrap_or(0) - now())
    }

    // ---------------------------------------------------------------- background work

    pub fn spawn_fetch(&mut self) {
        if self.loading {
            return;
        }
        self.loading = true;
        self.last_fetch = Some(Instant::now());
        let (config, role, tx) = (self.config.clone(), self.role, self.tx.clone());
        tokio::spawn(async move {
            let result = fetch(&config, role).await.map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Data(Box::new(result)));
        });
    }
    fn spawn_logs(&mut self) {
        if self.logs_loading || self.loading {
            return;
        }
        self.logs_loading = true;
        self.last_logs = Some(Instant::now());
        let (config, tx) = (self.config.clone(), self.tx.clone());
        tokio::spawn(async move {
            if let Ok(data) = admin(&config, AdminRequest::Logs { lines: 1000 }).await {
                let _ = tx.send(Msg::Logs(lines_of(&data)));
            } else {
                let _ = tx.send(Msg::Logs(Vec::new()));
            }
        });
    }
    fn spawn_health(&mut self) {
        if self.health_loading {
            return;
        }
        self.health_loading = true;
        let (path, tx) = (self.config_path.clone(), self.tx.clone());
        tokio::spawn(async move {
            let result = async {
                let output = tokio::process::Command::new(std::env::current_exe()?)
                    .arg("--config")
                    .arg(&path)
                    .args(["--json", "doctor"])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .await?;
                let text = String::from_utf8_lossy(&output.stdout);
                serde_json::from_str::<Value>(text.trim()).map_err(|_| {
                    anyhow::anyhow!(
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                            .lines()
                            .rfind(|l| !l.starts_with('{'))
                            .unwrap_or("doctor failed")
                    )
                })
            }
            .await
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Health(result));
        });
    }
    fn spawn_op(&mut self, op: Op, form: bool) {
        self.busy += 1;
        let (config, tx) = (self.config.clone(), self.tx.clone());
        tokio::spawn(async move {
            let result = execute(&config, op).await.map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Done { form, result });
        });
    }
    fn spawn_command(&mut self, line: String) {
        let args = match split_args(&line) {
            Ok(args) => args,
            Err(e) => return self.notify(e, Level::Error),
        };
        let mut args: Vec<String> = args;
        if args.first().map(String::as_str) == Some("rift") {
            args.remove(0);
        }
        if args.is_empty() {
            return;
        }
        let first = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .cloned()
            .unwrap_or_default();
        let second = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .nth(1)
            .cloned()
            .unwrap_or_default();
        match (first.as_str(), second.as_str()) {
            ("server" | "agent", _) => {
                return self.notify(
                    "server and agent run the daemon; they cannot run from here".into(),
                    Level::Error,
                )
            }
            ("tui", _) => return self.notify("this is the terminal UI".into(), Level::Info),
            ("export" | "import" | "backup" | "restore" | "proxy", _)
            | (_, "site")
            | ("list", "sites") => {
                return self.notify(
                    format!("`rift {first}` runs on the host: leave the terminal UI (q) and run it there with sudo. Sites can be managed on the Sites tab."),
                    Level::Warn,
                )
            }
            _ => {}
        }
        self.history.retain(|h| *h != line);
        self.history.push(line.clone());
        self.busy += 1;
        let (path, tx) = (self.config_path.clone(), self.tx.clone());
        tokio::spawn(async move {
            let result = async {
                Ok::<_, anyhow::Error>(
                    tokio::process::Command::new(std::env::current_exe()?)
                        .arg("--config")
                        .arg(&path)
                        .args(&args)
                        .stdin(std::process::Stdio::null())
                        .output()
                        .await?,
                )
            }
            .await
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Command { line, result });
        });
    }

    pub fn notify(&mut self, text: String, level: Level) {
        self.toast = Some(Toast {
            text,
            level,
            at: Instant::now(),
        });
    }

    // ---------------------------------------------------------------- messages

    pub fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Event(event) => self.on_event(event),
            Msg::Data(result) => {
                self.loading = false;
                match *result {
                    Ok(snapshot) => {
                        self.traffic.sample(&snapshot.status["peers"]);
                        self.snapshot = Some(snapshot);
                        self.fetch_error = None;
                        self.clamp_selections();
                    }
                    Err(e) => self.fetch_error = Some(e),
                }
            }
            Msg::Logs(lines) => {
                self.logs_loading = false;
                if let Some(snapshot) = &mut self.snapshot {
                    if !lines.is_empty() {
                        if !self.logs.follow {
                            // Keep the view on the same entries while new ones arrive.
                            let added = lines.len().saturating_sub(snapshot.logs.len());
                            if snapshot.logs.len() == 1000 {
                                self.logs.scroll += new_entries(&snapshot.logs, &lines);
                            } else {
                                self.logs.scroll += added;
                            }
                        }
                        snapshot.logs = lines;
                    }
                }
            }
            Msg::Health(result) => {
                self.health_loading = false;
                self.health = Some(result);
                self.clamp_selections();
            }
            Msg::Command { line, result } => {
                self.busy = self.busy.saturating_sub(1);
                let lines = match result {
                    Ok(output) => {
                        let mut lines: Vec<Line<'static>> = Vec::new();
                        for l in String::from_utf8_lossy(&output.stdout).lines() {
                            lines.push(Line::raw(l.to_string()));
                        }
                        // The daemon's structured log lines on stderr are not output.
                        for l in String::from_utf8_lossy(&output.stderr)
                            .lines()
                            .filter(|l| !(l.starts_with('{') && l.contains("\"level\"")))
                        {
                            lines.push(Line::styled(l.to_string(), super::theme::warn()));
                        }
                        if !output.status.success() {
                            lines.push(Line::raw(""));
                            lines.push(Line::styled(
                                format!("exit status {}", output.status.code().unwrap_or(-1)),
                                super::theme::bad(),
                            ));
                        }
                        if lines.is_empty() {
                            lines.push(Line::styled("(no output)", super::theme::muted()));
                        }
                        lines
                    }
                    Err(e) => vec![Line::styled(e, super::theme::bad())],
                };
                self.modals.push(Modal::Text {
                    title: format!("rift {line}"),
                    lines,
                    scroll: 0,
                    copy: Vec::new(),
                });
                self.spawn_fetch();
            }
            Msg::Done { form, result } => {
                self.busy = self.busy.saturating_sub(1);
                if form {
                    match (&result, self.modals.last_mut()) {
                        (Err(e), Some(Modal::Form { form, .. })) => {
                            form.error = Some(e.clone());
                            return;
                        }
                        (Ok(_), Some(Modal::Form { .. })) => {
                            self.modals.pop();
                        }
                        _ => {}
                    }
                }
                match result {
                    Ok(Done::Message { text, warn }) => {
                        if text.lines().count() > 2 || text.chars().count() > 160 {
                            self.modals.push(text_modal(
                                if warn { "Done, with warnings" } else { "Done" },
                                &text,
                            ));
                        } else {
                            self.notify(text, if warn { Level::Warn } else { Level::Info });
                        }
                    }
                    Ok(Done::Modal(modal)) => self.modals.push(*modal),
                    Ok(Done::Site { id, title }) => self.modals.push(Modal::Site {
                        title,
                        id,
                        started: Instant::now(),
                        result: None,
                        scroll: 0,
                    }),
                    Ok(Done::Password(password)) => self.password = Some(password),
                    Err(e) => self.notify(e, Level::Error),
                }
                self.spawn_fetch();
            }
        }
    }

    pub fn on_tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        if self.last_fetch.is_none_or(|at| at.elapsed() >= REFRESH) {
            self.spawn_fetch();
        }
        if matches!(self.current(), Tab::Logs | Tab::Overview)
            && self.last_logs.is_none_or(|at| at.elapsed() >= LOG_REFRESH)
        {
            self.spawn_logs();
        }
        if let Some(toast) = &self.toast {
            let keep = match toast.level {
                Level::Info => 5,
                Level::Warn => 10,
                Level::Error => 12,
            };
            if toast.at.elapsed() > Duration::from_secs(keep) {
                self.toast = None;
            }
        }
        // Site requests: the host service answers in the queue directory.
        let mut refresh = false;
        for modal in &mut self.modals {
            if let Modal::Site {
                id,
                started,
                result: result @ None,
                ..
            } = modal
            {
                let queue = std::path::Path::new(sites::QUEUE_DIR);
                // Still queued: nobody picked it up. Picked up: an import or backup may run long.
                let waiting = queue.join(format!("{id}.json")).exists();
                match sites::result(queue, id) {
                    Ok(answer) if answer["done"] == true => {
                        let mut message = answer["message"].as_str().unwrap_or_default().to_string();
                        if message.contains("request has exactly the keys") {
                            message.push_str("\n\nThe host helper is older than this RIFT: update it with sudo sh deploy/install-cli on the server.");
                        }
                        *result = Some((answer["ok"] == true, message));
                        refresh = true;
                    }
                    Ok(_) if waiting && started.elapsed() > SITE_WAIT => {
                        *result = Some((false, HOST_MISSING.into()))
                    }
                    Ok(_) if started.elapsed() > SITE_RUN => {
                        *result = Some((
                            false,
                            "The host service took the request but has not answered after three minutes; see journalctl -u rift-site-queue on the server.".into(),
                        ))
                    }
                    Ok(_) => {}
                    Err(e) => *result = Some((false, format!("{e:#}"))),
                }
            }
        }
        if refresh {
            self.spawn_fetch();
        }
    }

    // ---------------------------------------------------------------- input

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => self.on_key(key),
            Event::Mouse(mouse) => self.on_mouse(mouse),
            Event::Paste(text) => {
                if let Some(Modal::Form { form, .. }) = self.modals.last_mut() {
                    form.paste(&text);
                } else if let Some(command) = &mut self.command {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        let at = byte_index(&command.input, command.cursor);
                        command.input.insert(at, c);
                        command.cursor += 1;
                    }
                }
            }
            _ => {}
        }
    }

    fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            if self.modals.is_empty() && self.command.is_none() {
                self.quit = true;
            } else {
                self.modals.clear();
                self.command = None;
            }
            return;
        }
        if !self.modals.is_empty() {
            return self.modal_key(key);
        }
        if self.command.is_some() {
            return self.command_key(key);
        }
        let tab = self.current();
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') if !ctrl => self.quit = true,
            KeyCode::Tab | KeyCode::Right => self.switch((self.tab + 1) % self.tabs.len()),
            KeyCode::BackTab | KeyCode::Left => {
                self.switch((self.tab + self.tabs.len() - 1) % self.tabs.len())
            }
            KeyCode::Char(c @ '0'..='9') => {
                // 1 is the first tab, 0 the tenth.
                let i = (c as usize - '0' as usize + 9) % 10;
                if i < self.tabs.len() {
                    self.switch(i);
                }
            }
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => self.move_selection(-100_000),
            KeyCode::End => self.move_selection(100_000),
            KeyCode::Enter => self.context_menu(),
            KeyCode::F(5) => self.act(Act::Refresh),
            KeyCode::Char('l') if ctrl => self.act(Act::Refresh),
            KeyCode::Esc => self.toast = None,
            KeyCode::Delete => {
                if let Some((_, _, act)) = self.actions().into_iter().find(|(k, _, _)| *k == "x") {
                    self.act(act);
                }
            }
            KeyCode::Char(c) if !ctrl => {
                let key = c.to_string();
                if let Some((_, _, act)) = self
                    .actions()
                    .into_iter()
                    .chain(global_actions(self.role))
                    .find(|(k, _, _)| *k == key)
                {
                    self.act(act);
                } else {
                    // Vim-style movement where no action uses the letter.
                    match c {
                        'k' => self.move_selection(-1),
                        'j' => self.move_selection(1),
                        'g' => self.move_selection(-100_000),
                        'G' => self.move_selection(100_000),
                        ' ' if tab == Tab::Logs => self.act(Act::LogFollow),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn switch(&mut self, tab: usize) {
        self.tab = tab;
        match self.current() {
            Tab::Health if self.health.is_none() => self.spawn_health(),
            Tab::Logs => self.spawn_logs(),
            _ => {}
        }
    }

    fn move_selection(&mut self, by: i64) {
        let tab = self.current();
        if tab == Tab::Logs {
            let total = self.snapshot.as_ref().map_or(0, |s| s.logs.len());
            let scroll = (self.logs.scroll as i64 - by).clamp(0, total as i64) as usize;
            self.logs.scroll = scroll;
            self.logs.follow = scroll == 0;
            return;
        }
        let len = self.items(tab).len();
        if len == 0 {
            return;
        }
        let state = self.table(tab);
        let current = state.selected().unwrap_or(0) as i64;
        state.select(Some((current + by).clamp(0, len as i64 - 1) as usize));
    }

    fn command_key(&mut self, key: KeyEvent) {
        let Some(command) = &mut self.command else {
            return;
        };
        let len = command.input.chars().count();
        match key.code {
            KeyCode::Esc => self.command = None,
            KeyCode::Enter => {
                let line = command.input.trim().to_string();
                self.command = None;
                if !line.is_empty() {
                    self.spawn_command(line);
                }
            }
            KeyCode::Up if !self.history.is_empty() => {
                let back = command
                    .back
                    .map_or(self.history.len() - 1, |b| b.saturating_sub(1));
                command.back = Some(back);
                command.input = self.history[back].clone();
                command.cursor = command.input.chars().count();
            }
            KeyCode::Down => {
                if let Some(back) = command.back {
                    if back + 1 < self.history.len() {
                        command.back = Some(back + 1);
                        command.input = self.history[back + 1].clone();
                    } else {
                        command.back = None;
                        command.input.clear();
                    }
                    command.cursor = command.input.chars().count();
                }
            }
            KeyCode::Tab => {
                if let Some(completed) = complete(&command.input) {
                    command.input = completed;
                    command.cursor = command.input.chars().count();
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                command.input.clear();
                command.cursor = 0;
            }
            KeyCode::Char(c) => {
                let at = byte_index(&command.input, command.cursor);
                command.input.insert(at, c);
                command.cursor += 1;
            }
            KeyCode::Backspace if command.cursor > 0 => {
                let at = byte_index(&command.input, command.cursor - 1);
                command.input.remove(at);
                command.cursor -= 1;
            }
            KeyCode::Backspace => self.command = None,
            KeyCode::Delete if command.cursor < len => {
                let at = byte_index(&command.input, command.cursor);
                command.input.remove(at);
            }
            KeyCode::Left => command.cursor = command.cursor.saturating_sub(1),
            KeyCode::Right => command.cursor = (command.cursor + 1).min(len),
            KeyCode::Home => command.cursor = 0,
            KeyCode::End => command.cursor = len,
            _ => {}
        }
    }

    fn modal_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.modals.last_mut() else {
            return;
        };
        match modal {
            Modal::Form { form, .. } => match form.key(key) {
                Outcome::None => {}
                Outcome::Cancel => {
                    self.modals.pop();
                }
                Outcome::Submit => self.submit_form(),
            },
            Modal::Confirm { yes, .. } => match key.code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => *yes = !*yes,
                KeyCode::Char('y') => self.confirm(true),
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => self.confirm(false),
                KeyCode::Enter => {
                    let yes = *yes;
                    self.confirm(yes)
                }
                _ => {}
            },
            Modal::Menu { items, index, .. } => {
                let n = items.len().max(1);
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => {
                        self.modals.pop();
                    }
                    KeyCode::Up | KeyCode::Char('k') => *index = (*index + n - 1) % n,
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => *index = (*index + 1) % n,
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        let i = *index;
                        self.choose(i)
                    }
                    _ => {}
                }
            }
            Modal::Text { scroll, copy, .. } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.modals.pop();
                }
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::PageDown | KeyCode::Char(' ') => *scroll = scroll.saturating_add(10),
                KeyCode::Home | KeyCode::Char('g') => *scroll = 0,
                KeyCode::Char(c @ ('y' | '1'..='9')) => {
                    let index = if c == 'y' {
                        0
                    } else {
                        c as usize - '1' as usize
                    };
                    if let Some(item) = copy.get(index) {
                        let (text, what) = (item.text.clone(), item.what);
                        self.copy(&text, what);
                    }
                }
                _ => {}
            },
            Modal::Qr {
                show_text, scroll, ..
            } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.modals.pop();
                }
                KeyCode::Char('t') => {
                    *show_text = !*show_text;
                    *scroll = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::Char('y') => {
                    if let Some(Modal::Qr { text, .. }) = self.modals.last() {
                        let text = text.clone();
                        self.copy(&text, "the text");
                    }
                }
                _ => {}
            },
            Modal::Site { result, scroll, .. } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::PageDown => *scroll = scroll.saturating_add(10),
                _ if result.is_some() || key.code == KeyCode::Esc => {
                    self.modals.pop();
                }
                _ => {}
            },
            Modal::Help { scroll } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                _ => {
                    self.modals.pop();
                }
            },
        }
    }

    fn on_mouse(&mut self, mouse: MouseEvent) {
        let position = Position::new(mouse.column, mouse.row);
        let hit = self
            .hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(position))
            .map(|(_, h)| *h);
        match mouse.kind {
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let down = mouse.kind == MouseEventKind::ScrollDown;
                if let Some(modal) = self.modals.last_mut() {
                    match modal {
                        Modal::Text { scroll, .. }
                        | Modal::Qr { scroll, .. }
                        | Modal::Site { scroll, .. }
                        | Modal::Help { scroll } => {
                            *scroll = if down {
                                scroll.saturating_add(3)
                            } else {
                                scroll.saturating_sub(3)
                            }
                        }
                        Modal::Menu { items, index, .. } => {
                            let n = items.len().max(1);
                            *index = if down {
                                (*index + 1) % n
                            } else {
                                (*index + n - 1) % n
                            };
                        }
                        _ => {}
                    }
                } else {
                    let step = if self.current() == Tab::Logs { 3 } else { 1 };
                    self.move_selection(if down { step } else { -step });
                }
            }
            MouseEventKind::Down(button) => {
                if let Some(Modal::Form { form, .. }) = self.modals.last_mut() {
                    if button == MouseButton::Left {
                        match form.click(position) {
                            Outcome::None => {}
                            Outcome::Cancel => {
                                self.modals.pop();
                            }
                            Outcome::Submit => self.submit_form(),
                        }
                    }
                    return;
                }
                let double = button == MouseButton::Left
                    && self.last_click.is_some_and(|(at, h)| {
                        Some(h) == hit && at.elapsed() < Duration::from_millis(450)
                    });
                self.last_click = hit.map(|h| (Instant::now(), h));
                match hit {
                    None if !self.modals.is_empty() => {
                        // A click beside a menu or text closes it; a confirmation stays.
                        if !matches!(self.modals.last(), Some(Modal::Confirm { .. })) {
                            self.modals.pop();
                        }
                    }
                    None => {}
                    Some(hit) => self.click(hit, button, double),
                }
            }
            _ => {}
        }
    }

    fn click(&mut self, hit: Hit, button: MouseButton, double: bool) {
        match hit {
            Hit::Tab(i) => self.switch(i),
            Hit::Row(tab, i) => {
                self.table(tab).select(Some(i));
                if button == MouseButton::Right || double {
                    self.context_menu();
                }
            }
            Hit::Menu => self.context_menu(),
            Hit::Act(act) => self.act(act),
            Hit::MenuItem(i) => {
                if let Some(Modal::Menu { index, .. }) = self.modals.last_mut() {
                    *index = i;
                }
                self.choose(i);
            }
            Hit::Yes => self.confirm(true),
            Hit::No => self.confirm(false),
            Hit::Close => {
                self.modals.pop();
            }
            Hit::Copy(index) => {
                let found = match self.modals.last() {
                    Some(Modal::Text { copy, .. }) => {
                        copy.get(index).map(|c| (c.text.clone(), c.what))
                    }
                    Some(Modal::Qr { text, .. }) => Some((text.clone(), "the text")),
                    _ => None,
                };
                if let Some((text, what)) = found {
                    self.copy(&text, what);
                }
            }
            Hit::QrToggle => {
                if let Some(Modal::Qr {
                    show_text, scroll, ..
                }) = self.modals.last_mut()
                {
                    *show_text = !*show_text;
                    *scroll = 0;
                }
            }
            Hit::ModalArea | Hit::LogScroll => {}
        }
    }

    /// Copies text to the clipboard of the terminal (OSC 52), which works over SSH and
    /// `docker exec` in most terminals.
    fn copy(&mut self, text: &str, what: &str) {
        use base64::Engine;
        use std::io::Write;
        let encoded = base64::engine::general_purpose::STANDARD.encode(text);
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]52;c;{encoded}\x07");
        let _ = out.flush();
        self.notify(
            format!("Copied {what} to the clipboard (if your terminal allows OSC 52); otherwise select the text with Shift held down."),
            Level::Info,
        );
    }

    fn confirm(&mut self, yes: bool) {
        if let Some(Modal::Confirm { op, .. }) = self.modals.pop() {
            if yes {
                self.spawn_op(op, false);
            }
        }
    }

    fn choose(&mut self, index: usize) {
        let Some(Modal::Menu { items, .. }) = self.modals.last_mut() else {
            return;
        };
        if index >= items.len() || matches!(items[index].what, MenuWhat::Disabled) {
            return;
        }
        let Some(Modal::Menu { mut items, .. }) = self.modals.pop() else {
            return;
        };
        match items.swap_remove(index).what {
            MenuWhat::Act(act) => self.act(act),
            MenuWhat::Op(op) => self.spawn_op(*op, false),
            MenuWhat::Disabled => {}
            MenuWhat::Focus(agent) => {
                self.focus = agent;
                for tab in [Tab::Forwards, Tab::Devices, Tab::Sites, Tab::Bans] {
                    self.table(tab).select(Some(0));
                }
                self.clamp_selections();
            }
        }
    }

    fn context_menu(&mut self) {
        let actions = self.actions();
        if actions.is_empty() {
            return;
        }
        let title = match self.selected() {
            Some(item) => describe(self.current(), &item),
            None => self.current().title().to_string(),
        };
        // What concerns the selected row first, creating something new last.
        let (adds, rest): (Vec<_>, Vec<_>) = actions.into_iter().partition(|(_, _, act)| {
            matches!(
                act,
                Act::Invite | Act::ForwardAdd | Act::DeviceAdd | Act::SiteAdd | Act::BanAdd
            )
        });
        let items = rest
            .into_iter()
            .chain(adds)
            .map(|(key, label, act)| MenuItem {
                label,
                hint: key.to_string(),
                what: MenuWhat::Act(act),
            })
            .collect();
        self.modals.push(Modal::Menu {
            title,
            items,
            index: 0,
        });
    }

    // ---------------------------------------------------------------- actions

    /// The actions of the current tab for the selected row: (key, label, action).
    pub fn actions(&self) -> Vec<(&'static str, String, Act)> {
        let item = self.selected();
        let item = item.as_ref();
        let mut out: Vec<(&'static str, String, Act)> = Vec::new();
        let mut add = |key: &'static str, label: &str, act: Act| out.push((key, label.into(), act));
        match (self.role, self.current()) {
            (Role::Server, Tab::Overview) => {
                add("a", "Invite agent", Act::Invite);
                add("f", "Add forward", Act::ForwardAdd);
                add("d", "Add device", Act::DeviceAdd);
                add("R", "Reconcile", Act::Reconcile);
            }
            (Role::Server, Tab::Agents) => {
                add("a", "Invite", Act::Invite);
                add("/", "Filter", Act::Filter);
                if item.is_some_and(|a| a["invite"] == true) {
                    add("t", "New token", Act::NewToken);
                    add("c", "Cancel invitation", Act::CancelInvite);
                } else if let Some(agent) = item {
                    let name = agent["name"].as_str().unwrap_or_default();
                    let invited = self.invite_left(name).is_some();
                    match agent["status"].as_str() {
                        Some("active") => add("e", "Disable", Act::AgentToggle),
                        Some("disabled") => add("e", "Enable", Act::AgentToggle),
                        _ => {}
                    }
                    if agent["status"] == "active" {
                        add("f", "Add forward", Act::AgentForward);
                    }
                    add("r", "Rename", Act::AgentRename);
                    if agent["status"] != "pending" {
                        add("K", "Rotate key", Act::AgentRotate);
                    }
                    if agent["dns_name"].is_string() {
                        add(
                            "n",
                            if agent["names"] == true {
                                "Names off"
                            } else {
                                "Names on"
                            },
                            Act::AgentNames,
                        );
                    }
                    add("i", "Details", Act::AgentDetails);
                    if invited {
                        add("c", "Cancel invitation", Act::CancelInvite);
                    }
                    add("x", "Remove", Act::AgentRemove);
                }
            }
            (Role::Server, Tab::Forwards) => {
                add("a", "Add", Act::ForwardAdd);
                add("/", "Filter", Act::ForwardFilter);
                add("s", "Sort", Act::ForwardSort);
                if let Some(forward) = item {
                    if forward["purpose"] != "exit" {
                        add(
                            "e",
                            if forward["enabled"] == true {
                                "Disable"
                            } else {
                                "Enable"
                            },
                            Act::ForwardToggle,
                        );
                    }
                    if forward["mode"] == "translate" {
                        add("b", "Ban address", Act::ForwardBan);
                    }
                    if forward["purpose"] != "exit" {
                        add("x", "Remove", Act::ForwardRemove);
                    }
                }
            }
            (Role::Agent, Tab::Forwards) => {
                if item.is_some_and(|f| f["mode"] == "translate") {
                    add("b", "Ban address", Act::ForwardBan);
                }
                add("/", "Filter", Act::ForwardFilter);
                add("s", "Sort", Act::ForwardSort);
            }
            (Role::Server, Tab::Devices) => {
                add("a", "Add", Act::DeviceAdd);
                add("/", "Filter", Act::Filter);
                if let Some(device) = item {
                    add("g", "Grant access", Act::DeviceGrant);
                    if device["grants"].as_array().is_some_and(|g| !g.is_empty()) {
                        add("u", "Withdraw", Act::DeviceDeny);
                    }
                    add("c", "Config / QR", Act::DeviceConfig);
                    add("i", "Internet exits", Act::DeviceExits);
                    add("s", "DNS", Act::DeviceDns);
                    add(
                        "n",
                        if device["names_off"] == true {
                            "Names on"
                        } else {
                            "Names off"
                        },
                        Act::DeviceNames,
                    );
                    if self.overview()["panel"]["enabled"] == true {
                        add(
                            "p",
                            if device["panel"] == true {
                                "Panel off"
                            } else {
                                "Panel on"
                            },
                            Act::DevicePanel,
                        );
                    }
                    add(
                        "e",
                        if device["enabled"] == true {
                            "Disable"
                        } else {
                            "Enable"
                        },
                        Act::DeviceToggle,
                    );
                    add("x", "Remove", Act::DeviceRemove);
                }
            }
            (Role::Server, Tab::Sites) => {
                add("a", "Add", Act::SiteAdd);
                add("/", "Filter", Act::Filter);
                if item.is_some() {
                    add("x", "Remove", Act::SiteRemove);
                }
            }
            (Role::Server, Tab::Bans) => {
                add("a", "Ban address", Act::BanAdd);
                add("/", "Filter", Act::Filter);
            }
            (Role::Server, Tab::Panel) => {
                if self.overview()["panel"]["enabled"] == true {
                    add(
                        "p",
                        if self.password.is_some() {
                            "Hide password"
                        } else {
                            "Show password"
                        },
                        Act::Password,
                    );
                    add("s", "Set up 2FA", Act::TwoFactorSetup);
                    add("c", "Confirm 2FA code", Act::TwoFactorConfirm);
                    add("z", "Reset 2FA", Act::TwoFactorReset);
                    add("g", "Grant device", Act::PanelGrant);
                    add("w", "Withdraw device", Act::PanelWithdraw);
                }
            }
            (_, Tab::Logs) => {
                add(
                    "f",
                    if self.logs.follow { "Pause" } else { "Follow" },
                    Act::LogFollow,
                );
                add("/", "Filter", Act::LogFilter);
                add("v", "Level", Act::LogLevel);
            }
            (_, Tab::Health) => add("r", "Run checks", Act::HealthRun),
            (Role::Server, Tab::Backup) => {
                add("e", "Export settings", Act::Export);
                add("b", "Backup with keys", Act::Backup);
                if item.is_some_and(|f| f["kind"] == "export") {
                    add("i", "Import this file", Act::Import);
                }
            }
            _ => {}
        }
        out
    }

    pub fn act(&mut self, act: Act) {
        let item = self.selected().unwrap_or(Value::Null);
        let name = item["name"].as_str().unwrap_or_default().to_string();
        let id = item["id"].as_u64().unwrap_or(0);
        let requests = |r: Vec<AdminRequest>| Op::Requests(r);
        match act {
            Act::Quit => self.quit = true,
            Act::Help => self.modals.push(Modal::Help { scroll: 0 }),
            Act::Command => {
                self.command = Some(CommandLine {
                    input: String::new(),
                    cursor: 0,
                    back: None,
                })
            }
            Act::Refresh => {
                self.last_fetch = None;
                self.spawn_fetch();
                if self.current() == Tab::Health {
                    self.spawn_health();
                }
            }
            Act::Reconcile => self.spawn_op(requests(vec![AdminRequest::Reload]), false),
            Act::Invite => self.open_form(
                Form::new(
                    "Invite an agent",
                    "Create invitation",
                    vec![
                        Field::text("name", "Agent name", "", "e.g. node1")
                            .hint("letters, digits, - and _; an existing name re-invites it"),
                        Field::text("ttl", "Valid for", "15m", "15m"),
                    ],
                )
                .intro("Creates a single-use invitation. Run the printed command on the agent host."),
                Submit::Invite,
            ),
            Act::AgentToggle => {
                let request = if item["status"] == "active" {
                    AdminRequest::AgentDisable { name: name.clone() }
                } else {
                    AdminRequest::AgentEnable { name: name.clone() }
                };
                if item["status"] == "active" {
                    self.ask(
                        "Disable agent",
                        &format!("Disable {name}? Its forwards and VPN access stop until it is enabled again."),
                        requests(vec![request]),
                        true,
                    );
                } else {
                    self.spawn_op(requests(vec![request]), false);
                }
            }
            Act::AgentRename => self.open_form(
                Form::new(
                    &format!("Rename {name}"),
                    "Rename",
                    vec![Field::text("name", "New name", &name, "node2")],
                ),
                Submit::Rename(name),
            ),
            Act::AgentRotate => self.ask(
                "Rotate key",
                &format!("Give {name} a new WireGuard key? It happens on the agent's next sync."),
                requests(vec![AdminRequest::AgentRotate { name: name.clone() }]),
                false,
            ),
            Act::AgentNames => self.spawn_op(
                requests(vec![AdminRequest::AgentNames {
                    name,
                    on: item["names"] != true,
                }]),
                false,
            ),
            Act::AgentDetails => self.spawn_op(Op::Details(AdminRequest::AgentsShow { name }), false),
            Act::CancelInvite => self.ask(
                "Cancel invitation",
                &format!("Cancel the open invitation for {name}?"),
                requests(vec![AdminRequest::CancelInvite { name: name.clone() }]),
                true,
            ),
            Act::NewToken => self.ask(
                "New token",
                &format!("Replace the invitation for {name} with a new one, valid for 15 minutes? The old token stops working."),
                Op::Invite {
                    name: name.clone(),
                    ttl_seconds: 15 * 60,
                    replace: true,
                },
                false,
            ),
            Act::AgentRemove => self.ask(
                "Remove agent",
                &format!("Remove {name} with all its forwards and VPN grants? This cannot be undone."),
                requests(vec![AdminRequest::AgentRemove { name: name.clone() }]),
                true,
            ),
            Act::AgentForward => self.forward_form(Some(&name)),
            Act::ForwardAdd => self.forward_form(None),
            Act::ForwardToggle => {
                let enabled = item["enabled"] != true;
                self.spawn_op(
                    requests(vec![AdminRequest::ForwardEnable { id, enabled }]),
                    false,
                )
            }
            Act::ForwardRemove => self.ask(
                "Remove forward",
                &format!("Remove forward {id} ({})?", describe(Tab::Forwards, &item)),
                requests(vec![AdminRequest::ForwardRemove { id }]),
                true,
            ),
            Act::ForwardBan | Act::BanAdd => self.ban_form(
                (act == Act::ForwardBan).then_some(id),
            ),
            Act::DeviceAdd => {
                let mut fields = vec![Field::text("name", "Device name", "", "e.g. phone")];
                if self.overview()["panel"]["enabled"] == true {
                    fields.push(Field::check("panel", "May open the web panel", false));
                }
                self.open_form(
                    Form::new("Add a VPN device", "Add device", fields).intro(
                        "A device (phone, laptop) reaches nothing until you grant it access (g).",
                    ),
                    Submit::Device,
                )
            }
            Act::DeviceGrant => self.grant_form(&name),
            Act::DeviceDeny => {
                let mut items = Vec::new();
                let mut agents: Vec<String> = Vec::new();
                for grant in item["grants"].as_array().into_iter().flatten() {
                    let agent = grant["agent"].as_str().unwrap_or("?").to_string();
                    let Ok(access) = serde_json::from_value::<VpnAccess>(grant["access"].clone())
                    else {
                        continue;
                    };
                    items.push(MenuItem {
                        label: format!("{agent}: {}", output::vpn_access(&grant["access"])),
                        hint: String::new(),
                        what: MenuWhat::op(requests(vec![AdminRequest::VpnDeny {
                            peer: name.clone(),
                            agent: agent.clone(),
                            access: Some(access),
                        }])),
                    });
                    if !agents.contains(&agent) {
                        agents.push(agent);
                    }
                }
                for agent in agents {
                    items.push(MenuItem {
                        label: format!("{agent}: everything, including the exit through it"),
                        hint: String::new(),
                        what: MenuWhat::op(requests(vec![AdminRequest::VpnDeny {
                            peer: name.clone(),
                            agent,
                            access: None,
                        }])),
                    });
                }
                self.menu(&format!("Withdraw access of {name}"), items);
            }
            Act::DeviceConfig => {
                let mut items = vec![MenuItem {
                    label: "Main profile".into(),
                    hint: "grants, panel, server exit".into(),
                    what: MenuWhat::op(Op::Config {
                        name: name.clone(),
                        agent: None,
                    }),
                }];
                for exit in item["exits"].as_array().into_iter().flatten() {
                    if let Some(agent) = exit["agent"].as_str() {
                        items.push(MenuItem {
                            label: format!("Exit profile through {agent}"),
                            hint: exit["state"].as_str().unwrap_or_default().into(),
                            what: MenuWhat::op(Op::Config {
                                name: name.clone(),
                                agent: Some(agent.into()),
                            }),
                        });
                    }
                }
                if items.len() == 1 {
                    self.spawn_op(
                        Op::Config {
                            name,
                            agent: None,
                        },
                        false,
                    );
                } else {
                    self.menu(&format!("WireGuard configuration of {name}"), items);
                }
            }
            Act::DeviceExits => {
                let exits: Vec<&Value> = item["exits"].as_array().into_iter().flatten().collect();
                let server_on = exits.iter().any(|e| e["via"] == "server");
                let mut items = vec![MenuItem {
                    label: format!(
                        "{} Exit through this server",
                        if server_on { "[✓]" } else { "[ ]" }
                    ),
                    hint: "main profile".into(),
                    what: MenuWhat::op(requests(vec![if server_on {
                        AdminRequest::VpnExitClear {
                            peer: name.clone(),
                            agent: None,
                        }
                    } else {
                        AdminRequest::VpnExit {
                            peer: name.clone(),
                            exit: Exit::Server,
                        }
                    }])),
                }];
                for agent in self.status()["snapshot"]["agents"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|a| a["status"] == "active")
                {
                    let agent_name = agent["name"].as_str().unwrap_or_default().to_string();
                    let on = exits
                        .iter()
                        .any(|e| e["agent"].as_str() == Some(agent_name.as_str()));
                    let refuses = agent["limits"]["exit"] == false;
                    let request = if on {
                        AdminRequest::VpnExitClear {
                            peer: name.clone(),
                            agent: Some(agent_name.clone()),
                        }
                    } else {
                        AdminRequest::VpnExit {
                            peer: name.clone(),
                            exit: Exit::Agent(agent_name.clone()),
                        }
                    };
                    items.push(MenuItem {
                        label: format!(
                            "{} Exit through {agent_name}",
                            if on { "[✓]" } else { "[ ]" }
                        ),
                        hint: if refuses && !on {
                            "agent refuses exits (RIFT_AGENT_ALLOW_EXIT)".into()
                        } else {
                            "own profile".into()
                        },
                        what: if refuses && !on {
                            MenuWhat::Disabled
                        } else {
                            MenuWhat::op(requests(vec![request]))
                        },
                    });
                }
                self.menu(&format!("Internet exits of {name}"), items);
            }
            Act::DeviceDns => {
                let mut items = vec![MenuItem {
                    label: "Default".into(),
                    hint: "no DNS line, or RIFT_VPN_DNS with an exit".into(),
                    what: MenuWhat::op(requests(vec![AdminRequest::VpnDns {
                        peer: name.clone(),
                        agent: None,
                    }])),
                }];
                for agent in self.agent_names(true) {
                    items.push(MenuItem {
                        label: format!("DNS server on {agent}"),
                        hint: "e.g. AdGuard or Pi-hole there".into(),
                        what: MenuWhat::op(requests(vec![AdminRequest::VpnDns {
                            peer: name.clone(),
                            agent: Some(agent),
                        }])),
                    });
                }
                self.menu(&format!("DNS of {name}"), items);
            }
            Act::DeviceNames => self.spawn_op(
                requests(vec![AdminRequest::VpnPeerNames {
                    name,
                    on: item["names_off"] == true,
                }]),
                false,
            ),
            Act::DevicePanel => self.spawn_op(
                requests(vec![AdminRequest::PanelAllow {
                    name,
                    allowed: item["panel"] != true,
                }]),
                false,
            ),
            Act::DeviceToggle => {
                let enabled = item["enabled"] != true;
                let op = requests(vec![AdminRequest::VpnPeerEnable {
                    name: name.clone(),
                    enabled,
                }]);
                if enabled {
                    self.spawn_op(op, false)
                } else {
                    self.ask(
                        "Disable device",
                        &format!("Disable {name}? It can no longer connect; it keeps its key and grants."),
                        op,
                        true,
                    )
                }
            }
            Act::DeviceRemove => self.ask(
                "Remove device",
                &format!("Remove {name} with its key and grants? This cannot be undone; the device needs a new configuration afterwards."),
                requests(vec![AdminRequest::VpnPeerRevoke { name: name.clone() }]),
                true,
            ),
            Act::SiteAdd => self.site_form(),
            Act::SiteRemove => {
                let host = item["host"].as_str().unwrap_or_default().to_string();
                match sites::remove(&host) {
                    Ok(request) => self.ask(
                        "Remove site",
                        &format!("Remove the site {host} and its forward?"),
                        Op::Site {
                            request,
                            title: format!("Removing {host}"),
                        },
                        true,
                    ),
                    Err(e) => self.notify(format!("{e:#}"), Level::Error),
                }
            }
            Act::Password => {
                if self.password.take().is_none() {
                    self.spawn_op(Op::Password, false);
                }
            }
            Act::TwoFactorSetup => {
                let on = self.overview()["two_factor"]["enabled"] == true;
                let text = if on {
                    "Two-factor login is on. A new secret replaces it once confirmed with a code."
                } else {
                    "Create a secret for an authenticator app? It is shown once, as a QR code."
                };
                self.ask("Two-factor login", text, Op::TwoFactorSetup, false)
            }
            Act::TwoFactorConfirm => self.open_form(
                Form::new(
                    "Confirm two-factor login",
                    "Turn on",
                    vec![Field::text("code", "Code from the app", "", "six digits")],
                )
                .intro("After setting it up (s), type the current six-digit code to turn two-factor login on."),
                Submit::TwoFactorConfirm,
            ),
            Act::TwoFactorReset => self.ask(
                "Reset two-factor login",
                "Delete the secret and end all panel sessions? Use this when the authenticator app is lost.",
                requests(vec![AdminRequest::PanelTwoFactorReset]),
                true,
            ),
            Act::PanelGrant | Act::PanelWithdraw => {
                let grant = act == Act::PanelGrant;
                let items: Vec<MenuItem> = self
                    .unfiltered(Tab::Devices)
                    .iter()
                    .filter(|d| (d["panel"] == true) != grant)
                    .filter_map(|d| d["name"].as_str())
                    .map(|device| MenuItem {
                        label: device.to_string(),
                        hint: String::new(),
                        what: MenuWhat::op(requests(vec![AdminRequest::PanelAllow {
                            name: device.into(),
                            allowed: grant,
                        }])),
                    })
                    .collect();
                if items.is_empty() {
                    self.notify(
                        if grant {
                            "Every device may open the panel already, or there is none: add one on the VPN devices tab."
                        } else {
                            "No device may open the panel."
                        }
                        .into(),
                        Level::Info,
                    );
                } else {
                    self.menu(
                        if grant {
                            "Let a device open the panel"
                        } else {
                            "Withdraw panel access"
                        },
                        items,
                    );
                }
            }
            Act::LogFollow => {
                self.logs.follow = !self.logs.follow;
                if self.logs.follow {
                    self.logs.scroll = 0;
                }
            }
            Act::LogFilter => self.open_form(
                Form::new(
                    "Filter the log",
                    "Apply",
                    vec![Field::text("filter", "Contains", &self.logs.filter, "text, empty for all")],
                ),
                Submit::LogFilter,
            ),
            Act::LogLevel => self.logs.level = (self.logs.level + 1) % 4,
            Act::ForwardFilter => self.open_form(
                Form::new(
                    "Filter forwards",
                    "Apply",
                    vec![Field::text(
                        "filter",
                        "Show",
                        &self.forward_filter,
                        "empty for everything, or e.g. homelab 8080 udp",
                    )
                    .hint("all words must match; agent:NAME port:N proto:tcp state:pending")],
                )
                .intro("A number matches the ID or a listen or target port, also inside a range; other words match part of the agent, address, protocol, mode, ingress, state or allowed clients. Empty shows everything."),
                Submit::ForwardFilter,
            ),
            Act::Filter => {
                let tab = self.current();
                let current = self.filters.get(&tab).cloned().unwrap_or_default();
                self.open_form(
                    Form::new(
                        &format!("Filter {}", tab.title().to_lowercase()),
                        "Apply",
                        vec![Field::text("filter", "Show", &current, "empty for everything, or words that must all appear")
                            .hint("matches names, addresses, ports, agents, states; empty shows everything")],
                    ),
                    Submit::Filter(tab),
                );
            }
            Act::Focus => {
                let mut items = vec![MenuItem {
                    label: "All agents".into(),
                    hint: if self.focus.is_none() { "shown".into() } else { String::new() },
                    what: MenuWhat::Focus(None),
                }];
                for name in self
                    .unfiltered(Tab::Agents)
                    .iter()
                    .filter(|a| a["invite"] != true)
                    .filter_map(|a| a["name"].as_str())
                {
                    items.push(MenuItem {
                        label: name.to_string(),
                        hint: if self.focus.as_deref() == Some(name) {
                            "shown".into()
                        } else {
                            String::new()
                        },
                        what: MenuWhat::Focus(Some(name.to_string())),
                    });
                }
                self.menu("Show forwards, devices, sites and bans of", items);
            }
            Act::ForwardSort => {
                self.forward_query.sort = self.forward_query.sort.next();
                self.table(Tab::Forwards).select(Some(0));
                self.notify(
                    format!("Forwards sorted by {}.", self.forward_query.sort.name()),
                    Level::Info,
                );
            }
            Act::HealthRun => self.spawn_health(),
            Act::Export => self.spawn_op(
                Op::Site {
                    request: sites::export_kept(),
                    title: "Exporting the settings".into(),
                },
                false,
            ),
            Act::Backup => self.ask(
                "Backup",
                &format!("Save a backup with every key of this server (WireGuard, enrollment CA, VPN devices, panel password) in {} on the host? Copy it somewhere safe afterwards.", sites::FILES_DIR),
                Op::Site {
                    request: sites::backup_kept(),
                    title: "Saving a backup".into(),
                },
                false,
            ),
            Act::Import => {
                let files: Vec<(String, String)> = self
                    .items(Tab::Backup)
                    .iter()
                    .filter(|f| f["kind"] == "export")
                    .filter_map(|f| f["name"].as_str().map(|n| (n.to_string(), n.to_string())))
                    .collect();
                if files.is_empty() {
                    return self.notify(
                        format!("No export file in {} on the host.", sites::FILES_DIR),
                        Level::Warn,
                    );
                }
                let selected = item["name"].as_str().unwrap_or_default().to_string();
                self.open_form(
                    Form::new(
                        "Import settings",
                        "Import",
                        vec![
                            Field::select("file", "File", files).selected(&selected),
                            Field::text("map", "Agent names", "", "OLD=NEW, e.g. node2=node1")
                                .hint("put the entries of agent OLD on agent NEW"),
                            Field::check("dry_run", "Only show what would happen", true),
                        ],
                    )
                    .intro("Creates what the file holds and this server lacks: forwards, devices with their grants, sites. Agents are never created; add and enroll them first. Run it once as a dry run."),
                    Submit::Import,
                );
            }
        }
    }

    fn open_form(&mut self, form: Form, submit: Submit) {
        self.modals.push(Modal::Form { form, submit });
    }
    fn menu(&mut self, title: &str, items: Vec<MenuItem>) {
        if items.is_empty() {
            return self.notify("Nothing to choose from.".into(), Level::Info);
        }
        self.modals.push(Modal::Menu {
            title: title.into(),
            items,
            index: 0,
        });
    }
    fn ask(&mut self, title: &str, text: &str, op: Op, danger: bool) {
        self.modals.push(Modal::Confirm {
            title: title.into(),
            text: text.into(),
            op,
            danger,
            yes: !danger,
        });
    }

    fn agent_options(&self) -> Vec<(String, String)> {
        self.agent_names(true)
            .into_iter()
            .map(|n| (n.clone(), n))
            .collect()
    }

    fn forward_form(&mut self, agent: Option<&str>) {
        let agents = self.agent_options();
        if agents.is_empty() {
            return self.notify(
                "No active agent yet. Invite one first (Agents → a).".into(),
                Level::Warn,
            );
        }
        let ipv6 = self.config.public_ips.iter().any(|ip| ip.is_ipv6());
        let mut on = vec![("v4".to_string(), "IPv4 address".to_string())];
        if ipv6 {
            on.push(("v6".into(), "IPv6 address".into()));
            on.push(("all".into(), "IPv4 and IPv6".into()));
        }
        let form = Form::new(
            "Add forwards",
            "Add",
            vec![
                Field::select("agent", "Agent", agents).selected(agent.unwrap_or_default()),
                Field::text(
                    "specs",
                    "Ports",
                    "",
                    "e.g. 8080:80/tcp 53/both 5000-5002/udp",
                )
                .hint("LISTEN[:TARGET]/tcp|udp|both, several separated by spaces"),
                Field::select("on", "Listen on", on),
                Field::select(
                    "mode",
                    "Mode",
                    vec![
                        (
                            "transparent".into(),
                            "transparent (client address kept)".into(),
                        ),
                        ("translate".into(), "translate (IPv4 ⇄ IPv6)".into()),
                    ],
                ),
                Field::select(
                    "ingress",
                    "Ingress",
                    vec![
                        ("public".into(), "public".into()),
                        ("local".into(), "local (not from public NICs)".into()),
                    ],
                ),
                Field::text(
                    "allow_from",
                    "Only from",
                    "",
                    "empty for everyone, or e.g. 203.0.113.7 198.51.100.0/24",
                ),
            ],
        );
        self.open_form(form, Submit::Forward);
    }

    fn ban_form(&mut self, forward: Option<u64>) {
        let forwards: Vec<(String, String)> = self
            .all_forwards()
            .iter()
            .filter(|f| f["mode"] == "translate")
            .map(|f| (f["id"].to_string(), describe(Tab::Forwards, f)))
            .collect();
        if forwards.is_empty() {
            return self.notify(
                "Bans apply to translated forwards only, and there is none.".into(),
                Level::Warn,
            );
        }
        let form = Form::new(
            "Ban an address",
            "Ban",
            vec![
                Field::select("forward", "Forward", forwards)
                    .selected(&forward.map(|f| f.to_string()).unwrap_or_default()),
                Field::text("ip", "Client address", "", "e.g. 198.51.100.7"),
                Field::text("ttl", "For", "1h", "1h"),
            ],
        )
        .intro("Blocks an original client address on a translated forward.");
        self.open_form(form, Submit::Ban);
    }

    fn grant_form(&mut self, device: &str) {
        let agents = self.agent_options();
        if agents.is_empty() {
            return self.notify(
                "No active agent yet. Invite one first (Agents → a).".into(),
                Level::Warn,
            );
        }
        let form = Form::new(
            &format!("Grant {device} access"),
            "Grant",
            vec![
                Field::select("agent", "Agent", agents),
                Field::text(
                    "ports",
                    "Ports",
                    "",
                    "optional, e.g. 22/tcp 53/both 8000-8010/tcp",
                ),
                Field::check("server", "Whole host (TCP, UDP, ping)", false),
                Field::check("full", "All protocols", false),
                Field::text(
                    "subnets",
                    "LAN networks",
                    "",
                    "optional, e.g. 192.168.178.0/24",
                ),
                Field::check("snat", "Masquerade (SNAT) in the LAN", false)
                    .hint("when the LAN has no route back to the VPN"),
                Field::check("exit", "Internet exit through it", false)
                    .hint("a WireGuard profile of its own"),
            ],
        );
        self.open_form(form, Submit::Grant(device.into()));
    }

    fn site_form(&mut self) {
        let agents = self.agent_options();
        if agents.is_empty() {
            return self.notify(
                "No active agent yet. Invite one first (Agents → a).".into(),
                Level::Warn,
            );
        }
        let form = Form::new(
            "Add a site",
            "Add site",
            vec![
                Field::select("agent", "Agent", agents),
                Field::text("host", "Domain", "", "e.g. app.example.net"),
                Field::text("port", "Port on the agent", "", "e.g. 8080"),
                Field::select(
                    "proxy",
                    "Proxy",
                    vec![
                        (String::new(), "default (rift proxy)".into()),
                        ("traefik".into(), "Traefik".into()),
                        ("caddy".into(), "Caddy".into()),
                        ("nginx".into(), "Nginx".into()),
                        ("npm".into(), "Nginx Proxy Manager".into()),
                    ],
                ),
                Field::text("allow_from", "Only from", "", "empty for everyone, or e.g. 203.0.113.7 198.51.100.0/24"),
            ],
        )
        .intro("Publishes https://DOMAIN through the reverse proxy to this port. The domain must already point at this server.");
        self.open_form(form, Submit::Site);
    }

    fn submit_form(&mut self) {
        let Some(Modal::Form { form, submit }) = self.modals.last_mut() else {
            return;
        };
        if let Submit::LogFilter = submit {
            self.logs.filter = form.text("filter");
            self.logs.scroll = 0;
            self.modals.pop();
            return;
        }
        if let Submit::Filter(tab) = submit {
            let (tab, text) = (*tab, form.text("filter"));
            if text.is_empty() {
                self.filters.remove(&tab);
            } else {
                self.filters.insert(tab, text);
            }
            self.modals.pop();
            self.table(tab).select(Some(0));
            self.clamp_selections();
            return;
        }
        if let Submit::ForwardFilter = submit {
            let text = form.text("filter");
            match crate::query::ForwardQuery::parse(&text) {
                Ok(query) => {
                    let sort = self.forward_query.sort;
                    self.forward_query = crate::query::ForwardQuery { sort, ..query };
                    self.forward_filter = text;
                    self.modals.pop();
                    self.table(Tab::Forwards).select(Some(0));
                    self.clamp_selections();
                }
                Err(e) => form.error = Some(format!("{e:#}")),
            }
            return;
        }
        let submit = submit.clone();
        let form_copy = form.clone();
        match self.build(&submit, &form_copy) {
            Ok(op) => {
                if let Some(Modal::Form { form, .. }) = self.modals.last_mut() {
                    form.error = None;
                }
                self.spawn_op(op, true);
            }
            Err(e) => {
                if let Some(Modal::Form { form, .. }) = self.modals.last_mut() {
                    form.error = Some(format!("{e:#}"));
                }
            }
        }
    }

    /// The operation a submitted form asks for, checked as far as possible before it runs.
    fn build(&self, submit: &Submit, form: &Form) -> anyhow::Result<Op> {
        Ok(match submit {
            Submit::Invite => {
                let name = form.text("name");
                validate_name(&name)?;
                // An open invitation of that name is replaced; the old token stops working.
                let replace = self
                    .unfiltered(Tab::Agents)
                    .iter()
                    .any(|a| a["invite"] == true && a["name"].as_str() == Some(name.as_str()));
                Op::Invite {
                    name,
                    ttl_seconds: webpanel::seconds(&form.text("ttl"))?,
                    replace,
                }
            }
            Submit::Rename(old) => {
                let new_name = form.text("name");
                validate_name(&new_name)?;
                Op::Requests(vec![AdminRequest::AgentRename {
                    name: old.clone(),
                    new_name,
                }])
            }
            Submit::Forward => {
                let specs = webpanel::words(&form.text("specs"));
                anyhow::ensure!(
                    !specs.is_empty(),
                    "name at least one port with its protocol, for example 8080:80/tcp"
                );
                let on = match form.text("on").as_str() {
                    "v6" => ListenOn::V6,
                    "all" => ListenOn::All,
                    _ => ListenOn::V4,
                };
                let options = ForwardOptions {
                    on: Some(on),
                    mode: Some(if form.text("mode") == "translate" {
                        ForwardMode::Translate
                    } else {
                        ForwardMode::Transparent
                    }),
                    ingress: if form.text("ingress") == "local" {
                        Ingress::Local
                    } else {
                        Ingress::Public
                    },
                    allow_from: parse_allow_from(&[form.text("allow_from")])?,
                    ..Default::default()
                };
                let forwards = build_forwards(
                    &form.text("agent"),
                    &parse_forward_specs(&specs)?,
                    &self.config.public_ips,
                    options,
                )?;
                Op::Requests(forwards.into_iter().map(AdminRequest::ForwardAdd).collect())
            }
            Submit::Ban => Op::Requests(vec![AdminRequest::Ban {
                forward_id: form.text("forward").parse()?,
                ip: form
                    .text("ip")
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{:?} is not an IP address", form.text("ip")))?,
                ttl_seconds: webpanel::seconds(&form.text("ttl"))?,
            }]),
            Submit::Device => {
                let name = form.text("name");
                validate_name(&name)?;
                let mut requests = vec![AdminRequest::VpnPeerAdd { name: name.clone() }];
                if form.on("panel") {
                    requests.push(AdminRequest::PanelAllow {
                        name,
                        allowed: true,
                    });
                }
                Op::Requests(requests)
            }
            Submit::Grant(peer) => {
                let agent = form.text("agent");
                let subnets = webpanel::words(&form.text("subnets"))
                    .iter()
                    .map(|s| {
                        s.parse::<ipnet::Ipv4Net>()
                            .map_err(|_| anyhow::anyhow!("{s:?} is not an IPv4 network"))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let snat = form.on("snat");
                anyhow::ensure!(
                    !snat || !subnets.is_empty(),
                    "masquerading applies only to a LAN network"
                );
                let accesses = vpn::accesses(
                    form.on("server"),
                    form.on("full"),
                    &webpanel::words(&form.text("ports")),
                    &subnets,
                    snat,
                )?;
                let mut requests: Vec<AdminRequest> = accesses
                    .into_iter()
                    .map(|access| AdminRequest::VpnAllow {
                        peer: peer.clone(),
                        agent: agent.clone(),
                        access,
                    })
                    .collect();
                if form.on("exit") {
                    requests.push(AdminRequest::VpnExit {
                        peer: peer.clone(),
                        exit: Exit::Agent(agent),
                    });
                }
                anyhow::ensure!(
                    !requests.is_empty(),
                    "choose what to allow: ports, the whole host, all protocols, a LAN network or the exit"
                );
                Op::Requests(requests)
            }
            Submit::Site => {
                let host = form.text("host");
                let port: u32 = form
                    .text("port")
                    .parse()
                    .map_err(|_| anyhow::anyhow!("the port must be in 1..65535"))?;
                let proxy = form.text("proxy");
                let request = sites::add(
                    &form.text("agent"),
                    &host,
                    port,
                    (!proxy.is_empty()).then_some(proxy.as_str()),
                    &parse_allow_from(&[form.text("allow_from")])?,
                )?;
                Op::Site {
                    request,
                    title: format!("Adding {host}"),
                }
            }
            Submit::TwoFactorConfirm => Op::Requests(vec![AdminRequest::PanelTwoFactorConfirm {
                code: form.text("code").replace(' ', ""),
            }]),
            Submit::LogFilter | Submit::ForwardFilter | Submit::Filter(_) => {
                unreachable!("applied without an operation")
            }
            Submit::Import => {
                let file = form.text("file");
                let dry_run = form.on("dry_run");
                let document = sites::read_export(std::path::Path::new(sites::FILES_DIR), &file)?;
                Op::Site {
                    request: sites::import(document, dry_run, &form.text("map"))?,
                    title: if dry_run {
                        format!("Import of {file} (dry run)")
                    } else {
                        format!("Import of {file}")
                    },
                }
            }
        })
    }
}

/// One line naming a row, for menu titles and confirmations.
pub fn describe(tab: Tab, item: &Value) -> String {
    let s = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        v => v.to_string(),
    };
    match tab {
        Tab::Forwards => format!(
            "#{} {} {}/{} → {}:{}",
            s(&item["id"]),
            s(&item["agent"]),
            listen(&item["listen_ip"], &item["listen_ports"]),
            s(&item["protocol"]),
            s(&item["agent"]),
            range(&item["target_ports"]),
        ),
        Tab::Sites => s(&item["host"]),
        _ => s(&item["name"]),
    }
}
pub fn range(value: &Value) -> String {
    match (value["start"].as_u64(), value["end"].as_u64()) {
        (Some(a), Some(b)) if a == b => a.to_string(),
        (Some(a), Some(b)) => format!("{a}-{b}"),
        _ => "-".into(),
    }
}
pub fn listen(ip: &Value, ports: &Value) -> String {
    let ip = ip.as_str().unwrap_or("-");
    if ip.contains(':') {
        format!("[{ip}]:{}", range(ports))
    } else {
        format!("{ip}:{}", range(ports))
    }
}

pub fn text_modal(title: &str, text: &str) -> Modal {
    Modal::Text {
        title: title.into(),
        lines: text.lines().map(|l| Line::raw(l.to_string())).collect(),
        scroll: 0,
        copy: Vec::new(),
    }
}

fn global_actions(role: Role) -> Vec<(&'static str, String, Act)> {
    let mut actions = vec![
        (":", "Command".into(), Act::Command),
        ("?", "Help".into(), Act::Help),
    ];
    // Reconciling is the server's; an agent applies what the server sends.
    if role == Role::Server {
        actions.push(("R", "Reconcile".into(), Act::Reconcile));
        actions.push(("F", "Focus on an agent".into(), Act::Focus));
    }
    actions
}

/// How many entries `new` has after the last entry of `old`, for a log that is full.
fn new_entries(old: &[String], new: &[String]) -> usize {
    match old.last() {
        Some(last) => new
            .iter()
            .rposition(|l| l == last)
            .map_or(0, |i| new.len() - 1 - i),
        None => 0,
    }
}

fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(i, _)| i)
}

fn lines_of(data: &Value) -> Vec<String> {
    data["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| l.as_str().map(String::from))
        .collect()
}

/// Splits a command line like a shell: words separated by spaces, '…' and "…" quote.
pub fn split_args(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err("unclosed quote".into());
    }
    if started {
        args.push(current);
    }
    Ok(args)
}

/// Completes the last word of a command from the CLI's command words.
fn complete(input: &str) -> Option<String> {
    const WORDS: &[&str] = &[
        "status", "doctor", "list", "show", "add", "remove", "disable", "enable", "rename",
        "rotate", "vpn", "panel", "config", "reload", "logs", "agents", "agent", "forwards",
        "forward", "bans", "ban", "devices", "device", "invite", "allow", "deny", "dns", "names",
        "connect", "password", "2fa", "setup", "confirm", "reset", "validate", "exit", "server",
        "full", "--json", "--export", "--help",
    ];
    let start = input.rfind(' ').map_or(0, |i| i + 1);
    let word = &input[start..];
    if word.is_empty() {
        return None;
    }
    let matches: Vec<&str> = WORDS
        .iter()
        .copied()
        .filter(|w| w.starts_with(word))
        .collect();
    match matches.as_slice() {
        [] => None,
        [only] => Some(format!("{}{only} ", &input[..start])),
        [first, rest @ ..] => {
            // As far as all candidates agree.
            let common = rest.iter().fold(first.len(), |n, w| {
                first
                    .bytes()
                    .zip(w.bytes())
                    .take(n)
                    .take_while(|(a, b)| a == b)
                    .count()
            });
            (common > word.len()).then(|| format!("{}{}", &input[..start], &first[..common]))
        }
    }
}

/// What the terminal UI says after a request where the CLI's message names CLI commands as the
/// next step; `None` keeps the CLI's message.
fn in_ui(request: &AdminRequest, data: &Value) -> Option<String> {
    Some(match request {
        AdminRequest::VpnPeerAdd { name } => format!(
            "VPN device {name} added ({}, {}).\n\
             It reaches nothing yet. Next, on the VPN devices tab with {name} selected:\n  \
             g  grant access: ports, a LAN, the whole host of an agent, or an internet exit\n  \
             c  show its WireGuard configuration as a QR code to scan (or as text)",
            data["ipv4"].as_str().unwrap_or("-"),
            data["ipv6"].as_str().unwrap_or("-"),
        ),
        AdminRequest::PanelAllow {
            name,
            allowed: true,
        } => {
            let url = data["urls"]
                .as_array()
                .and_then(|u| u.get(1))
                .and_then(|u| u["url"].as_str())
                .unwrap_or("the panel");
            format!("{name} may open the web panel at {url} once its WireGuard tunnel is up.")
        }
        _ => return None,
    })
}

/// A QR code in half blocks with a two-module margin instead of the standard four, so a
/// WireGuard configuration fits a terminal of about 40 rows; phone scanners read it.
///
/// What it encodes is smaller than the text, so the code needs fewer rows: comment lines and
/// blank lines go (WireGuard ignores them; the text view keeps them), and the error correction
/// is level L, enough for a code read off a screen, which nothing smudges.
fn qr(text: &str) -> anyhow::Result<String> {
    use qrcode::{render::unicode::Dense1x2, EcLevel, QrCode};
    let payload: String = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L)?
        .render::<Dense1x2>()
        .quiet_zone(false)
        .build();
    let width = code.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    let blank = " ".repeat(width + 4);
    let mut out = vec![blank.clone()];
    out.extend(code.lines().map(|l| format!("  {l}  ")));
    out.push(blank);
    Ok(out.join("\n"))
}

async fn admin(config: &Config, request: AdminRequest) -> anyhow::Result<Value> {
    let response = crate::daemon::admin_call(config, request).await?;
    if !response.ok {
        anyhow::bail!(
            "{}",
            response.error.unwrap_or_else(|| "operation failed".into())
        );
    }
    Ok(response.data)
}

async fn fetch(config: &Config, role: Role) -> anyhow::Result<Snapshot> {
    let status = admin(config, AdminRequest::Status).await.map_err(|e| {
        anyhow::anyhow!("RIFT does not answer on its admin socket ({e:#}); is the daemon running?")
    })?;
    let logs = admin(config, AdminRequest::Logs { lines: 1000 })
        .await
        .map(|d| lines_of(&d))
        .unwrap_or_default();
    let overview = match role {
        Role::Server => {
            let peers = admin(config, AdminRequest::VpnPeerList).await?;
            let panel = admin(config, AdminRequest::PanelStatus).await?;
            let mut overview = webpanel::compose_overview(&status, &peers, &panel);
            let forwards = overview["forwards"].as_array().cloned().unwrap_or_default();
            overview["sites"] = sites::overview(
                std::path::Path::new(sites::SITES_DIR),
                std::path::Path::new(sites::QUEUE_DIR),
                &forwards,
            );
            overview["files"] = Value::Array(sites::files(std::path::Path::new(sites::FILES_DIR)));
            overview["two_factor"] = admin(config, AdminRequest::PanelTwoFactorStatus)
                .await
                .unwrap_or_default();
            overview
        }
        Role::Agent => {
            let forwards = admin(config, AdminRequest::ForwardsList)
                .await
                .unwrap_or_else(|_| json!([]));
            json!({ "forwards": forwards })
        }
    };
    Ok(Snapshot {
        status,
        overview,
        logs,
    })
}

async fn execute(config: &Config, op: Op) -> anyhow::Result<Done> {
    Ok(match op {
        Op::Requests(requests) => {
            let agents = if requests
                .iter()
                .any(|r| matches!(r, AdminRequest::ForwardAdd(_)))
            {
                admin(config, AdminRequest::AgentsList).await.ok()
            } else {
                None
            };
            let mut text = Vec::new();
            let mut warn = false;
            let mut reimport: Vec<Value> = Vec::new();
            let created: Vec<Value> = requests
                .iter()
                .filter_map(|r| match r {
                    AdminRequest::VpnPeerAdd { name } => Some(Value::from(name.clone())),
                    _ => None,
                })
                .collect();
            let total = requests.len();
            for (i, request) in requests.into_iter().enumerate() {
                let data = admin(config, request.clone()).await.map_err(|e| {
                    if i > 0 {
                        anyhow::anyhow!("{e:#} ({i} of {total} parts were already applied)")
                    } else {
                        e
                    }
                })?;
                if let Some(warning) = data["warning"].as_str() {
                    warn = true;
                    text.push(format!("Warning: {warning}"));
                }
                let mut shown = in_ui(&request, &data)
                    .unwrap_or_else(|| output::render(&request, &data, agents.as_ref()));
                if let AdminRequest::ForwardAdd(_) = request {
                    // The table header is noise in a notification; keep the first line.
                    shown = shown.lines().next().unwrap_or_default().to_string();
                }
                text.push(shown);
                if output::reimport_note(&request, &data).is_some() {
                    for device in data["reimport"].as_array().into_iter().flatten() {
                        if !reimport.contains(device) {
                            reimport.push(device.clone());
                        }
                    }
                }
            }
            // One note for all parts: which devices must import their configuration again. A
            // device created right now has nothing imported yet.
            reimport.retain(|device| !created.contains(device));
            let names: Vec<&str> = reimport.iter().filter_map(Value::as_str).collect();
            if !names.is_empty() {
                text.push(format!(
                    "Import the configuration of {} again on the device: VPN devices → c (it changed).",
                    names.join(", ")
                ));
            }
            Done::Message {
                text: text.join("\n"),
                warn,
            }
        }
        Op::Invite {
            name,
            ttl_seconds,
            replace,
        } => {
            if replace {
                admin(config, AdminRequest::CancelInvite { name: name.clone() }).await?;
            }
            let data = admin(config, AdminRequest::Invite { name, ttl_seconds }).await?;
            let (server, agent, token) = (
                data["server"].as_str().unwrap_or_default(),
                data["name"].as_str().unwrap_or_default(),
                data["token"].as_str().unwrap_or_default(),
            );
            let join = crate::enrollment::join_command(server, agent, token);
            let copy = vec![
                Copyable {
                    label: "Setup (1)",
                    what: "the setup commands (git clone, cd RIFT, deploy/join)",
                    text: format!("{}\n{join}\n", output::CHECKOUT),
                },
                Copyable {
                    label: "Join only (2)",
                    what: "the deploy/join line",
                    text: format!("{join}\n"),
                },
                Copyable {
                    label: ".env lines (3)",
                    what: "the three .env lines",
                    text: format!(
                        "RIFT_SERVER={server}\nRIFT_AGENT_NAME={agent}\nRIFT_ENROLLMENT_TOKEN={token}\n"
                    ),
                },
            ];
            let mut lines: Vec<Line<'static>> = Vec::new();
            for line in output::invitation(&data).lines() {
                let style = if line.starts_with("  ") || line.starts_with("RIFT_") {
                    super::theme::accent()
                } else {
                    ratatui::style::Style::new()
                };
                lines.push(Line::styled(line.to_string(), style));
            }
            Done::modal(Modal::Text {
                title: format!(
                    "Invitation for {}",
                    data["name"].as_str().unwrap_or_default()
                ),
                lines,
                scroll: 0,
                copy,
            })
        }
        Op::Config { name, agent } => {
            let data = admin(
                config,
                AdminRequest::VpnConfig {
                    name: name.clone(),
                    agent: agent.clone(),
                },
            )
            .await?;
            let text = data["config"].as_str().unwrap_or_default().to_string();
            Done::modal(Modal::Qr {
                title: match &agent {
                    Some(agent) => format!("{name} · exit through {agent}"),
                    None => format!("{name} · main profile"),
                },
                qr: qr(&text)?,
                text,
                note: "Scan in the WireGuard app. It contains the device's private key.".into(),
                show_text: false,
                scroll: 0,
            })
        }
        Op::TwoFactorSetup => {
            let data = admin(config, AdminRequest::PanelTwoFactorSetup).await?;
            let uri = data["uri"].as_str().unwrap_or_default().to_string();
            Done::modal(Modal::Qr {
                title: "Two-factor login".into(),
                qr: qr(&uri)?,
                text: format!(
                    "Secret: {}\nLink:   {uri}\n",
                    data["secret"].as_str().unwrap_or_default()
                ),
                note: "Scan with an authenticator app, then confirm a code (c). The secret is shown once.".into(),
                show_text: false,
                scroll: 0,
            })
        }
        Op::Password => {
            let data = admin(config, AdminRequest::PanelPassword).await?;
            Done::Password(data["password"].as_str().unwrap_or_default().to_string())
        }
        Op::Details(request) => {
            let data = admin(config, request.clone()).await?;
            let text = output::render(&request, &data, None);
            Done::modal(text_modal("Details", &text))
        }
        Op::Site { request, title } => {
            let id = sites::enqueue(std::path::Path::new(sites::QUEUE_DIR), &request)?;
            Done::Site { id, title }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_codes_keep_a_margin_and_fit_a_terminal() {
        let config = "[Interface]\nPrivateKey = cGhvbmUtcHJpdmF0ZS1rZXktZm9yLXRlc3Rpbmc=\nAddress = 10.14.0.2/32, fd88:5249:4655::2/128\nDNS = 9.9.9.9\n\n[Peer]\nPublicKey = c2VydmVyLXB1YmxpYy1rZXktZm9yLXRlc3Rpbmc=\nEndpoint = rift.example.net:51820\nAllowedIPs = 10.13.0.2/32, 192.168.178.0/24\nPersistentKeepalive = 25\n";
        let code = qr(config).unwrap();
        let lines: Vec<&str> = code.lines().collect();
        assert!(lines.len() <= 35, "{} rows", lines.len());
        assert!(lines[0].trim().is_empty() && lines.last().unwrap().trim().is_empty());
        assert!(lines
            .iter()
            .all(|l| l.starts_with("  ") && l.ends_with("  ")));
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
    }

    #[test]
    fn qr_codes_leave_out_comments_and_stay_small() {
        let exit = "# Internet exit via agent homelab. This profile carries all traffic through homelab's\n# connection; the web panel and other RIFT grants are not reachable with it.\n[Interface]\nPrivateKey = cGhvbmUtcHJpdmF0ZS1rZXktZm9yLXRlc3Rpbmc=\nAddress = 10.14.0.2/32, fd88:5249:4655::2/128\nDNS = 9.9.9.9, 2620:fe::fe\nMTU = 1300\n\n[Peer]\nPublicKey = c2VydmVyLXB1YmxpYy1rZXktZm9yLXRlc3Rpbmc=\nEndpoint = homelab.example.net:51821\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";
        let with_comments = crate::vpn::qr(exit).unwrap().lines().count();
        let rows = qr(exit).unwrap().lines().count();
        assert!(
            rows + 6 <= with_comments,
            "{rows} rows here, {with_comments} with comments"
        );
    }

    #[test]
    fn command_lines_split_like_a_shell() {
        assert_eq!(
            split_args(r#"add forward node1 "8080:80/tcp" '53/both'"#).unwrap(),
            vec!["add", "forward", "node1", "8080:80/tcp", "53/both"]
        );
        assert_eq!(
            split_args("  list   agents ").unwrap(),
            vec!["list", "agents"]
        );
        assert_eq!(
            split_args(r#"rename agent a """#).unwrap(),
            vec!["rename", "agent", "a", ""]
        );
        assert!(split_args("add 'x").is_err());
    }

    #[test]
    fn completion_extends_as_far_as_the_words_agree() {
        assert_eq!(complete("list ag").as_deref(), Some("list agent"));
        assert_eq!(complete("list agents").as_deref(), Some("list agents "));
        assert_eq!(complete("sta").as_deref(), Some("status "));
        assert_eq!(complete("re"), None);
        assert_eq!(complete(""), None);
    }

    #[test]
    fn traffic_rates_come_from_byte_counters() {
        let mut traffic = Traffic::default();
        traffic.sample(&json!([{"public_key":"k","rx_bytes":1000,"tx_bytes":0}]));
        assert!(traffic.rx.is_empty());
        traffic.at = Some(Instant::now() - Duration::from_secs(2));
        traffic.sample(&json!([{"public_key":"k","rx_bytes":3000,"tx_bytes":500}]));
        let (rx, tx) = traffic.rates["k"];
        assert!((900..=1000).contains(&rx), "{rx}");
        assert!((200..=250).contains(&tx), "{tx}");
        assert_eq!(traffic.rx.len(), 1);
        traffic.sample(&json!([]));
        assert!(traffic.rates.is_empty());
    }

    #[test]
    fn a_full_log_counts_the_entries_after_the_last_one_seen() {
        let old: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let new: Vec<String> = ["b", "c", "d", "e"].iter().map(|s| s.to_string()).collect();
        assert_eq!(new_entries(&old, &new), 2);
        assert_eq!(new_entries(&[], &new), 0);
    }

    #[test]
    fn rows_are_described_for_menus() {
        let forward = json!({"id":3,"agent":"node1","listen_ip":"2001:db8::1","listen_ports":{"start":80,"end":80},"protocol":"tcp","target_ports":{"start":8080,"end":8081}});
        assert_eq!(
            describe(Tab::Forwards, &forward),
            "#3 node1 [2001:db8::1]:80/tcp → node1:8080-8081"
        );
        assert_eq!(describe(Tab::Agents, &json!({"name":"pi"})), "pi");
    }
}
