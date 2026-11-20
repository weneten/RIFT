//! Drawing of the terminal UI. Every clickable thing records its area in `App::hits` while it
//! is drawn, so the mouse always hits what is on screen.

use super::{
    app::{listen, range, Act, App, Hit, Level, MenuWhat, Modal, Role, Tab},
    form::wrapped_lines,
    theme,
};
use crate::model::now;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Margin, Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Cell, Clear, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Sparkline, Table, Wrap,
    },
    Frame,
};
use serde_json::Value;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn draw(frame: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = frame.area();
    if area.width < 60 || area.height < 16 {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(theme::gradient("RIFT")),
                Line::raw(""),
                Line::raw("The window is too small."),
                Line::styled("At least 60 × 16 characters.", theme::muted()),
            ])
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
            area.inner(Margin::new(1, area.height.saturating_sub(4) / 2)),
        );
        return;
    }
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(frame, app, header);
    draw_tabs(frame, app, tabs);
    let body = body.inner(Margin::new(1, 0));
    if app.snapshot.is_none() {
        draw_waiting(frame, app, body);
    } else {
        match app.current() {
            Tab::Overview if app.role == Role::Server => draw_overview(frame, app, body),
            Tab::Overview => draw_agent_overview(frame, app, body),
            Tab::Agents => draw_agents(frame, app, body),
            Tab::Forwards => draw_forwards(frame, app, body),
            Tab::Devices => draw_devices(frame, app, body),
            Tab::Sites => draw_sites(frame, app, body),
            Tab::Bans => draw_bans(frame, app, body),
            Tab::Panel => draw_panel(frame, app, body),
            Tab::Logs => draw_logs(frame, app, body),
            Tab::Health => draw_health(frame, app, body),
            Tab::Backup => draw_backup(frame, app, body),
        }
    }
    draw_footer(frame, app, footer);
    draw_toast(frame, app, body);
    if !app.modals.is_empty() {
        // Only the top modal takes clicks.
        app.hits.clear();
        draw_modal(frame, app, area);
    }
}

// -------------------------------------------------------------------- frame

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut left = vec![Span::raw(" ")];
    left.extend(theme::gradient("▌RIFT"));
    if area.width >= 120 {
        left.push(Span::styled(
            "  Rust Internet Forwarding Tunnel",
            theme::muted(),
        ));
    }
    let role = match app.role {
        Role::Server => {
            let endpoint = &app.config.public_endpoint;
            format!("  ·  server {endpoint}")
        }
        Role::Agent => {
            let name = app.status()["identity"]["welcome"]["name"]
                .as_str()
                .map(String::from)
                .or_else(|| app.config.agent_name.clone())
                .unwrap_or_else(|| "agent".into());
            format!("  ·  agent {name}")
        }
    };
    left.push(Span::styled(role, theme::bold()));
    let mut right: Vec<Span> = Vec::new();
    if app.busy > 0 {
        right.push(Span::styled(
            format!("{} working ", SPINNER[app.frame % SPINNER.len()]),
            theme::accent(),
        ));
    }
    match (&app.fetch_error, app.role) {
        (Some(_), _) => right.push(Span::styled("● unreachable ", theme::bad())),
        (None, Role::Server) => {
            let status = app.status();
            if status["apply_error"].is_string() {
                right.push(Span::styled("● apply error ", theme::bad()));
            } else if status["fully_applied"] == true {
                right.push(Span::styled("● applied ", theme::ok()));
            } else if app.snapshot.is_some() {
                right.push(Span::styled("◐ applying ", theme::warn()));
            }
            if let Some(generation) = status["snapshot"]["generation"].as_u64() {
                right.push(Span::styled(format!("gen {generation} "), theme::muted()));
            }
        }
        (None, Role::Agent) => {
            if app.status()["connected"] == true {
                right.push(Span::styled("● connected ", theme::ok()));
            } else if app.snapshot.is_some() {
                right.push(Span::styled("● not connected ", theme::bad()));
            }
        }
    }
    if let Some(version) = app.status()["rift_version"].as_str() {
        right.push(Span::styled(format!("v{version} "), theme::muted()));
    }
    if area.width >= 90 {
        right.push(Span::styled(clock(), theme::muted()));
    }
    right.push(Span::raw(" "));
    let right_width: u16 = right.iter().map(|s| s.width() as u16).sum();
    frame.render_widget(Line::from(left), area);
    frame.render_widget(
        Line::from(right).alignment(Alignment::Right),
        Rect::new(
            area.x + area.width.saturating_sub(right_width),
            area.y,
            right_width.min(area.width),
            1,
        ),
    );
}

fn draw_tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    let mut x = area.x + 1;
    let y = area.y;
    // All tabs must fit: without counts and numbers on narrow windows.
    let full: usize = app.tabs.iter().map(|t| t.title().chars().count() + 9).sum();
    let compact = full > area.width as usize;
    for (i, tab) in app.tabs.clone().into_iter().enumerate() {
        let selected = i == app.tab;
        if compact {
            let title = tab.short();
            let width = title.chars().count() as u16 + 2;
            if x + width > area.x + area.width {
                break;
            }
            let style = if selected {
                theme::key()
            } else {
                Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD)
            };
            let rect = Rect::new(x, y, width, 1);
            frame.render_widget(Span::styled(format!(" {title} "), style), rect);
            app.hits.push((rect, Hit::Tab(i)));
            x += width;
            continue;
        }
        let count = match tab {
            Tab::Agents | Tab::Forwards | Tab::Devices | Tab::Sites | Tab::Bans => {
                let n = app.items(tab).len();
                (n > 0).then(|| format!(" ·{n}"))
            }
            _ => None,
        };
        let count = count.unwrap_or_default();
        let width = (tab.title().chars().count() + count.chars().count() + 5) as u16;
        if x + width > area.x + area.width {
            break;
        }
        let (number, title, extra) = if selected {
            (theme::key(), theme::key(), theme::key())
        } else {
            (theme::muted(), Style::new().fg(theme::TEXT), theme::muted())
        };
        let rect = Rect::new(x, y, width, 1);
        frame.render_widget(
            Line::from(vec![
                Span::styled(format!(" {} ", (i + 1) % 10), number),
                Span::styled(tab.title(), title.add_modifier(Modifier::BOLD)),
                Span::styled(format!("{count} "), extra),
            ]),
            rect,
        );
        app.hits.push((rect, Hit::Tab(i)));
        x += width + 1;
    }
    if let Some(agent) = &app.focus {
        let label = format!(" ◉ agent {agent} · F ");
        let width = label.chars().count() as u16;
        if x + width < area.x + area.width {
            let rect = Rect::new(area.x + area.width - width, y, width, 1);
            frame.render_widget(Span::styled(label, theme::key()), rect);
            app.hits.push((rect, Hit::Act(Act::Focus)));
        }
    }
    // A thin rule under the tabs.
    frame.render_widget(
        Paragraph::new("─".repeat(area.width as usize)).style(theme::border()),
        Rect::new(area.x, y + 1, area.width, 1),
    );
}

fn draw_footer(frame: &mut Frame, app: &mut App, area: Rect) {
    if let Some(command) = &app.command {
        let prompt = Span::styled(" rift ", theme::key());
        let text = Span::styled(format!(" {}", command.input), Style::new().fg(theme::TEXT));
        let hint = Span::styled(
            "   Enter run · Tab complete · ↑↓ history · Esc cancel",
            theme::muted(),
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![prompt, text, hint]))
                .style(Style::new().bg(theme::FIELD)),
            area,
        );
        let x = area.x + 7 + command.cursor as u16;
        if x < area.x + area.width {
            frame.set_cursor_position(Position::new(x, area.y));
        }
        return;
    }
    let mut x = area.x;
    let end = area.x + area.width;
    let globals = [
        (":", "Command", Act::Command),
        ("?", "Help", Act::Help),
        ("q", "Quit", Act::Quit),
    ];
    let global_width: u16 = globals
        .iter()
        .map(|(k, l, _)| (k.chars().count() + l.chars().count() + 4) as u16)
        .sum();
    let actions = app.actions();
    let mut buttons: Vec<(String, String, Act)> = actions
        .into_iter()
        .map(|(k, l, a)| (k.to_string(), l, a))
        .collect();
    if !buttons.is_empty() {
        buttons.insert(0, ("⏎".into(), "Menu".into(), Act::Refresh));
    }
    for (i, (key, label, act)) in buttons.iter().enumerate() {
        let width = (key.chars().count() + label.chars().count() + 4) as u16;
        if x + width + global_width > end {
            break;
        }
        frame.render_widget(
            Line::from(vec![
                Span::styled(format!(" {key} "), theme::key()),
                Span::styled(format!(" {label} "), Style::new().fg(theme::TEXT)),
            ]),
            Rect::new(x, area.y, width, 1),
        );
        // The first button ("⏎ Menu") opens the context menu; it is not an action itself.
        let hit = if i == 0 { Hit::Menu } else { Hit::Act(*act) };
        app.hits.push((Rect::new(x, area.y, width, 1), hit));
        x += width;
    }
    let mut x = end.saturating_sub(global_width);
    for (key, label, act) in globals {
        let width = (key.chars().count() + label.chars().count() + 4) as u16;
        frame.render_widget(
            Line::from(vec![
                Span::styled(format!(" {key} "), theme::button()),
                Span::styled(format!(" {label} "), theme::muted()),
            ]),
            Rect::new(x, area.y, width, 1),
        );
        app.hits
            .push((Rect::new(x, area.y, width, 1), Hit::Act(act)));
        x += width;
    }
}

fn draw_toast(frame: &mut Frame, app: &App, body: Rect) {
    let Some(toast) = &app.toast else {
        return;
    };
    let (icon, color) = match toast.level {
        Level::Info => ("✓", theme::OK),
        Level::Warn => ("!", theme::WARN),
        Level::Error => ("✗", theme::BAD),
    };
    let longest = toast
        .text
        .lines()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0);
    let width = (longest as u16 + 6)
        .min(body.width.saturating_sub(4))
        .min(90)
        .max(20.min(body.width));
    let height = wrapped_lines(&toast.text, width.saturating_sub(6)) + 2;
    let area = Rect::new(
        body.x + body.width.saturating_sub(width + 1),
        body.y + body.height.saturating_sub(height),
        width,
        height.min(body.height),
    );
    frame.render_widget(Clear, area);
    // One line per line of the text: a line break inside a span is not drawn, which ran the
    // sentences of a message together.
    let lines: Vec<Line> = toast
        .text
        .lines()
        .enumerate()
        .map(|(i, line)| {
            let lead = if i == 0 {
                Span::styled(format!("{icon} "), Style::new().fg(color).bold())
            } else {
                Span::raw("  ")
            };
            Line::from(vec![lead, Span::raw(line.to_string())])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(theme::popup())
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(color))
                    .style(theme::popup()),
            ),
        area,
    );
}

fn draw_waiting(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![
        Line::raw(""),
        Line::from(theme::gradient("R I F T")).alignment(Alignment::Center),
        Line::raw(""),
    ];
    match &app.fetch_error {
        Some(error) => {
            lines
                .push(Line::styled("Cannot reach the RIFT daemon", theme::bad().bold()).centered());
            lines.push(Line::styled(error.clone(), theme::muted()).centered());
            lines.push(Line::raw(""));
            lines.push(
                Line::styled("Retrying every few seconds · q quits", theme::muted()).centered(),
            );
        }
        None => lines.push(
            Line::styled(
                format!("{} Connecting…", SPINNER[app.frame % SPINNER.len()]),
                theme::accent(),
            )
            .centered(),
        ),
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }),
        area.inner(Margin::new(2, area.height / 4)),
    );
}

// -------------------------------------------------------------------- building blocks

fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(title.to_string(), theme::bold()),
            Span::raw(" "),
        ]))
        .padding(Padding::horizontal(1))
}

fn card(frame: &mut Frame, area: Rect, title: &str, value: Line<'static>, detail: Line<'static>) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Span::styled(format!(" {title} "), theme::muted()))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(vec![value, detail]), inner);
}

fn dot(state: &str) -> Span<'static> {
    match state {
        "ok" | "active" | "online" | "enabled" => Span::styled("●", theme::ok()),
        "warn" | "pending" | "waiting" => Span::styled("◐", theme::warn()),
        "bad" | "refused" | "error" | "offline" => Span::styled("●", theme::bad()),
        _ => Span::styled("○", theme::muted()),
    }
}

fn cell(content: impl Into<Line<'static>>) -> Line<'static> {
    content.into()
}

fn s(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(s) if s.is_empty() => "-".into(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

/// Renders a table with selection, a scrollbar and click areas for its rows.
#[allow(clippy::too_many_arguments)]
fn table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    tab: Tab,
    title: &str,
    header: &[&str],
    widths: &[Constraint],
    drop: &[usize],
    rows: Vec<Vec<Line<'static>>>,
    empty: &str,
) {
    let count = rows.len();
    let block = panel(title).title_bottom(
        Line::styled(
            if count > 0 {
                let i = app.tables.get(&tab).and_then(|t| t.selected()).unwrap_or(0);
                format!(" {}/{count} ", i + 1)
            } else {
                String::new()
            },
            theme::muted(),
        )
        .right_aligned(),
    );
    let inner = block.inner(area);
    let available = inner.width.saturating_sub(1);
    // Narrow windows: leave out whole columns, least important first, before squeezing the
    // rest. The details beside or below the table still show what they held.
    let keep = kept_columns(header, widths, &rows, drop, available);
    let header: Vec<&str> = pick(header, &keep);
    let widths: Vec<Constraint> = pick(widths, &keep);
    let rows: Vec<Vec<Line<'static>>> = rows.into_iter().map(|r| pick(&r, &keep)).collect();
    let widths = fit_columns(&header, &widths, &rows, available);
    let rows: Vec<Row<'static>> = rows
        .into_iter()
        .map(|cells| Row::new(cells.into_iter().map(Cell::from)))
        .collect();
    if count == 0 {
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(empty.to_string(), theme::muted()),
            ])
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    let header = Row::new(
        header
            .iter()
            .map(|h| Cell::from(Span::styled(h.to_string(), theme::muted().bold()))),
    )
    .height(1);
    let widget = Table::new(rows, widths)
        .header(header)
        .block(block)
        .column_spacing(2)
        .row_highlight_style(theme::selected())
        .highlight_symbol(Span::styled("▍", theme::accent()));
    let state = app.table(tab);
    frame.render_stateful_widget(widget, area, state);
    let offset = state.offset();
    let visible = inner.height.saturating_sub(1) as usize;
    for (n, i) in (offset..count.min(offset + visible)).enumerate() {
        app.hits.push((
            Rect::new(inner.x, inner.y + 1 + n as u16, inner.width, 1),
            Hit::Row(tab, i),
        ));
    }
    if count > visible {
        let mut scrollbar = ScrollbarState::new(count.saturating_sub(visible)).position(offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(theme::accent())
                .track_style(theme::border()),
            area.inner(Margin::new(0, 1)),
            &mut scrollbar,
        );
    }
}

const SPACING: u16 = 2;

/// Which columns stay: all that fit, dropping those in `drop` in its order while they do not.
fn kept_columns(
    header: &[&str],
    limits: &[Constraint],
    rows: &[Vec<Line<'static>>],
    drop: &[usize],
    available: u16,
) -> Vec<bool> {
    let natural = natural_widths(header, limits, rows);
    let mut keep = vec![true; header.len()];
    let need = |keep: &[bool]| -> u16 {
        let kept: Vec<u16> = natural
            .iter()
            .zip(keep)
            .filter(|(_, k)| **k)
            .map(|(w, _)| *w)
            .collect();
        kept.iter().sum::<u16>() + SPACING * kept.len().saturating_sub(1) as u16
    };
    for &column in drop {
        if need(&keep) <= available {
            break;
        }
        if let Some(k) = keep.get_mut(column) {
            *k = false;
        }
    }
    keep
}

fn pick<T: Clone>(items: &[T], keep: &[bool]) -> Vec<T> {
    items
        .iter()
        .zip(keep)
        .filter(|(_, k)| **k)
        .map(|(item, _)| item.clone())
        .collect()
}

/// Each column as wide as its content, within its limit.
fn natural_widths(header: &[&str], limits: &[Constraint], rows: &[Vec<Line<'static>>]) -> Vec<u16> {
    limits
        .iter()
        .enumerate()
        .map(|(c, limit)| {
            let content =
                rows.iter()
                    .filter_map(|r| r.get(c))
                    .map(Line::width)
                    .max()
                    .unwrap_or(0)
                    .max(header.get(c).map_or(0, |h| h.chars().count())) as u16;
            match *limit {
                Constraint::Length(cap) => content.min(cap),
                Constraint::Min(min) => content.clamp(min, 48),
                _ => content,
            }
        })
        .collect()
}

/// Column widths from the content: `Length(n)` caps a column at n, `Min(n)` keeps at least n
/// where possible. When the columns do not fit, the widest give way first, down to a few
/// characters, so every column stays visible.
fn fit_columns(
    header: &[&str],
    limits: &[Constraint],
    rows: &[Vec<Line<'static>>],
    available: u16,
) -> Vec<Constraint> {
    let mut widths = natural_widths(header, limits, rows);
    let floor: Vec<u16> = header
        .iter()
        .map(|h| (h.chars().count() as u16).clamp(1, 6))
        .collect();
    let spacing = SPACING * (widths.len().saturating_sub(1) as u16);
    while widths.iter().sum::<u16>() + spacing > available {
        let Some((i, _)) = widths
            .iter()
            .enumerate()
            .filter(|(i, w)| **w > floor.get(*i).copied().unwrap_or(1))
            .max_by_key(|(_, w)| **w)
        else {
            break;
        };
        widths[i] -= 1;
    }
    widths.into_iter().map(Constraint::Length).collect()
}

/// The table, and beside it (or below, on narrow windows) the details of the selected row.
fn split_detail(area: Rect, min_width: u16) -> (Rect, Option<Rect>) {
    if area.width >= min_width {
        let [left, right] =
            Layout::horizontal([Constraint::Min(60), Constraint::Length(44)]).areas(area);
        (left, Some(right))
    } else if area.height >= 24 {
        let [top, bottom] =
            Layout::vertical([Constraint::Min(8), Constraint::Length(10)]).areas(area);
        (top, Some(bottom))
    } else {
        (area, None)
    }
}

fn details(frame: &mut Frame, area: Rect, title: &str, lines: Vec<Line<'static>>) {
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(title)),
        area,
    );
}

fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<12}"), theme::muted()),
        // A value is one line; a line break inside a span would run its lines together.
        Span::raw(value.into().replace('\n', " ")),
    ])
}

// -------------------------------------------------------------------- overview

fn draw_overview(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .unfiltered(Tab::Agents)
        .len()
        .max(attention(app).len() + 1) as u16;
    let [cards, traffic, lists, logs] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(7),
        Constraint::Length((rows + 2).clamp(5, 14)),
        Constraint::Min(4),
    ])
    .areas(area);
    let overview = app.overview().clone();
    let agents = app.unfiltered(Tab::Agents);
    let forwards = app.all_forwards();
    let devices = app.unfiltered(Tab::Devices);
    let online = agents.iter().filter(|a| a["online"] == true).count();
    let enrolled = agents.iter().filter(|a| a["invite"] != true).count();
    let active_forwards = forwards
        .iter()
        .filter(|f| f["enabled"] == true && f["pending"] != true && f["refused"].is_null())
        .count();
    let problem_forwards = forwards
        .iter()
        .filter(|f| f["pending"] == true || !f["refused"].is_null())
        .count();
    let connected = devices
        .iter()
        .filter(|d| {
            d["last_handshake"]
                .as_i64()
                .is_some_and(|h| h > 0 && now() - h <= 180)
        })
        .count();
    let sites = app.unfiltered(Tab::Sites).len();
    let bans = app.unfiltered(Tab::Bans).len();
    let [a, b, c, d] = Layout::horizontal([Constraint::Ratio(1, 4); 4]).areas(cards);
    let big = |n: String, total: String, color: ratatui::style::Color| {
        Line::from(vec![
            Span::styled(n, Style::new().fg(color).bold()),
            Span::styled(total, theme::muted()),
        ])
    };
    card(
        frame,
        a,
        "Agents",
        big(
            online.to_string(),
            format!(" / {enrolled} online"),
            if online == enrolled {
                theme::OK
            } else {
                theme::WARN
            },
        ),
        Line::styled(
            format!(
                "{} invite(s) open",
                overview["invites"].as_array().map_or(0, Vec::len)
            ),
            theme::muted(),
        ),
    );
    card(
        frame,
        b,
        "Forwards",
        big(
            active_forwards.to_string(),
            format!(" / {} active", forwards.len()),
            theme::SKY,
        ),
        if problem_forwards > 0 {
            Line::styled(format!("{problem_forwards} pending/refused"), theme::warn())
        } else {
            Line::styled("all applied", theme::muted())
        },
    );
    card(
        frame,
        c,
        "VPN devices",
        big(
            connected.to_string(),
            format!(" / {} connected", devices.len()),
            theme::VIOLET,
        ),
        Line::styled(
            format!(
                "{} with panel",
                devices.iter().filter(|d| d["panel"] == true).count()
            ),
            theme::muted(),
        ),
    );
    card(
        frame,
        d,
        "Sites · Bans",
        big(
            sites.to_string(),
            format!(
                " site{} · {bans} ban{}",
                if sites == 1 { "" } else { "s" },
                if bans == 1 { "" } else { "s" }
            ),
            theme::ACCENT,
        ),
        Line::styled(
            match overview["enrollment"]["open"].as_bool() {
                Some(true) => "enrollment open".to_string(),
                _ => format!("enrollment {}", s(&overview["enrollment"]["mode"])),
            },
            theme::muted(),
        ),
    );
    draw_traffic(frame, app, traffic);
    let [left, right] = Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(lists);
    // Agents at a glance.
    let rates = agent_rates(app);
    let name_width = agents
        .iter()
        .map(|a| s(&a["name"]).chars().count())
        .max()
        .unwrap_or(0)
        .min(20);
    let mut lines = Vec::new();
    for agent in &agents {
        let name = s(&agent["name"]);
        let state = if agent["invite"] == true {
            "invited".to_string()
        } else if agent["status"] != "active" {
            agent["status"].as_str().unwrap_or("?").to_string()
        } else if agent["online"] == true {
            "online".into()
        } else {
            "offline".into()
        };
        let mut spans = vec![
            dot(&state),
            Span::raw(" "),
            Span::styled(
                format!("{name:<width$} ", width = name_width),
                theme::bold(),
            ),
            Span::styled(format!("{state:<8}"), theme::muted()),
        ];
        if agent["invite"] == true {
            let left = agent["expires_at"].as_i64().unwrap_or(0) - now();
            spans.push(Span::styled(
                format!("token valid {}", duration(left)),
                theme::accent(),
            ));
        }
        if let Some((rx, tx)) = rates.get(agent["id"].as_str().unwrap_or_default()) {
            spans.push(Span::styled(
                format!("↓{:>10} ", rate(*rx)),
                Style::new().fg(theme::SKY),
            ));
            spans.push(Span::styled(
                format!("↑{:>10}", rate(*tx)),
                Style::new().fg(theme::VIOLET),
            ));
        }
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::styled(
            "No agents yet. Press a to invite one.",
            theme::muted(),
        ));
    }
    frame.render_widget(Paragraph::new(lines).block(panel("Agents")), left);
    // What needs attention.
    let attention = attention(app);
    let lines: Vec<Line> = if attention.is_empty() {
        vec![Line::from(vec![
            Span::styled("✓ ", theme::ok()),
            Span::raw("Nothing needs attention."),
        ])]
    } else {
        attention
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Attention")),
        right,
    );
    draw_recent_logs(frame, app, logs);
}

fn draw_agent_overview(frame: &mut Frame, app: &mut App, area: Rect) {
    let [cards, traffic, rest] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(7),
        Constraint::Min(6),
    ])
    .areas(area);
    let status = app.status().clone();
    let identity = &status["identity"];
    let welcome = &identity["welcome"];
    let [a, b, c, d] = Layout::horizontal([Constraint::Ratio(1, 4); 4]).areas(cards);
    let connected = status["connected"] == true;
    card(
        frame,
        a,
        "Tunnel",
        Line::from(if connected {
            Span::styled("● connected", theme::ok().bold())
        } else {
            Span::styled("● not connected", theme::bad().bold())
        }),
        Line::styled(
            if identity["active"] == true {
                "enrolled, active"
            } else {
                "not active yet"
            },
            theme::muted(),
        ),
    );
    card(
        frame,
        b,
        "Server",
        Line::styled(s(&welcome["server_endpoint"]), theme::bold()),
        Line::styled(
            format!("tunnel {}", s(&welcome["server_ipv4"])),
            theme::muted(),
        ),
    );
    card(
        frame,
        c,
        "This agent",
        Line::styled(
            s(&welcome["tunnel_ipv4"]),
            Style::new().fg(theme::SKY).bold(),
        ),
        Line::styled(s(&welcome["tunnel_ipv6"]), theme::muted()),
    );
    let forwards = app.all_forwards();
    card(
        frame,
        d,
        "Forwards",
        Line::styled(
            forwards.len().to_string(),
            Style::new().fg(theme::ACCENT).bold(),
        ),
        Line::styled(
            format!("generation {}", s(&identity["applied_generation"])),
            theme::muted(),
        ),
    );
    draw_traffic(frame, app, traffic);
    let [left, right] = Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(rest);
    let mut lines = vec![
        kv("Name", s(&welcome["name"])),
        kv("Agent ID", s(&identity["id"])),
        kv("Keepalive", format!("{} s", s(&welcome["keepalive"]))),
        kv("MTU", s(&welcome["mtu"])),
    ];
    for peer in status["peers"].as_array().into_iter().flatten() {
        lines.push(kv(
            "Handshake",
            ago(peer["last_handshake"].as_i64().unwrap_or(0)),
        ));
        lines.push(kv("Endpoint", s(&peer["endpoint"])));
        lines.push(kv(
            "Transfer",
            format!(
                "↓ {}  ↑ {}",
                bytes(peer["rx_bytes"].as_u64().unwrap_or(0)),
                bytes(peer["tx_bytes"].as_u64().unwrap_or(0))
            ),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Identity")),
        left,
    );
    draw_recent_logs(frame, app, right);
}

fn draw_traffic(frame: &mut Frame, app: &App, area: Rect) {
    let block = panel("Traffic through the tunnel");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [labels, graphs] =
        Layout::horizontal([Constraint::Length(18), Constraint::Min(10)]).areas(inner);
    let [rx_area, tx_area] =
        Layout::vertical([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(graphs);
    let [rx_label, tx_label] =
        Layout::vertical([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(labels);
    let width = graphs.width as usize;
    let tail = |v: &std::collections::VecDeque<u64>| -> Vec<u64> {
        let skip = v.len().saturating_sub(width);
        v.iter().skip(skip).copied().collect()
    };
    let (rx, tx) = (tail(&app.traffic.rx), tail(&app.traffic.tx));
    let max = rx
        .iter()
        .chain(tx.iter())
        .copied()
        .max()
        .unwrap_or(0)
        .max(1);
    let current = |v: &[u64]| v.last().copied().unwrap_or(0);
    // The server's "received" is what the agents send: shown from the agents' side.
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("↓ in (received)", theme::muted()),
            Line::styled(rate(current(&rx)), Style::new().fg(theme::SKY).bold()),
        ]),
        rx_label,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("↑ out (sent)", theme::muted()),
            Line::styled(rate(current(&tx)), Style::new().fg(theme::VIOLET).bold()),
        ]),
        tx_label,
    );
    if rx.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled("collecting samples…", theme::muted())),
            graphs,
        );
        return;
    }
    frame.render_widget(
        Sparkline::default()
            .data(&rx)
            .max(max)
            .style(Style::new().fg(theme::SKY)),
        rx_area,
    );
    frame.render_widget(
        Sparkline::default()
            .data(&tx)
            .max(max)
            .style(Style::new().fg(theme::VIOLET)),
        tx_area,
    );
}

/// Bytes per second by agent ID (received, sent), from the WireGuard counters.
fn agent_rates(app: &App) -> std::collections::HashMap<String, (u64, u64)> {
    app.status()["snapshot"]["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let rate = app.traffic.rates.get(a["public_key"].as_str()?)?;
            Some((a["id"].as_str()?.to_string(), *rate))
        })
        .collect()
}

fn attention(app: &App) -> Vec<Line<'static>> {
    let status = app.status();
    let overview = app.overview();
    let mut lines = Vec::new();
    let mut push = |bad: bool, text: String| {
        lines.push(Line::from(vec![
            if bad {
                Span::styled("✗ ", theme::bad())
            } else {
                Span::styled("! ", theme::warn())
            },
            Span::raw(text.replace('\n', " ")),
        ]))
    };
    if let Some(error) = status["apply_error"].as_str() {
        push(true, format!("Configuration not applied: {error}"));
    }
    if let Some(error) = overview["panel"]["error"].as_str() {
        push(true, format!("Web panel {error}"));
    }
    for agent in app.unfiltered(Tab::Agents) {
        let name = s(&agent["name"]);
        if agent["status"] == "active" && agent["online"] != true {
            push(false, format!("Agent {name} is offline"));
        } else if agent["status"] == "active" && agent["configuration_ready"] != true {
            push(
                false,
                format!("Agent {name} has not applied the latest configuration"),
            );
        }
        if let Some(error) = agent["last_error"].as_str() {
            push(false, format!("Agent {name}: {error}"));
        }
    }
    for forward in app.all_forwards() {
        if let Some(reason) = forward["refused"].as_str() {
            push(
                false,
                format!("Forward {} refused: {reason}", forward["id"]),
            );
        }
    }
    for refused in status["refused_grants"].as_array().into_iter().flatten() {
        push(false, crate::output::refused_grant(refused));
    }
    for refused in status["refused_host_grants"]
        .as_array()
        .into_iter()
        .flatten()
    {
        push(false, crate::output::refused_host_grant(refused));
    }
    for stuck in status["inapplicable_forwards"]
        .as_array()
        .into_iter()
        .flatten()
    {
        push(
            false,
            format!("Forward {}: {}", stuck["id"], s(&stuck["reason"])),
        );
    }
    for invite in overview["invites"].as_array().into_iter().flatten() {
        let left = invite["expires_at"].as_i64().unwrap_or(0) - now();
        lines.push(Line::from(vec![
            Span::styled("◷ ", theme::accent()),
            Span::raw(format!(
                "Invitation for {} open, {} left",
                s(&invite["name"]),
                duration(left)
            )),
        ]));
    }
    if overview["sites"]["available"] == false && overview["sites"]["queue"] == false {
        lines.push(Line::from(vec![
            Span::styled("· ", theme::muted()),
            Span::styled(
                "Sites: the host helper is not installed (sudo sh deploy/install-cli)",
                theme::muted(),
            ),
        ]));
    }
    lines
}

fn draw_recent_logs(frame: &mut Frame, app: &App, area: Rect) {
    let block = panel("Recent log");
    let inner = block.inner(area);
    let logs = app.snapshot.as_ref().map(|s| &s.logs[..]).unwrap_or(&[]);
    let lines: Vec<Line> = logs
        .iter()
        .rev()
        .take(inner.height as usize)
        .rev()
        .map(|l| log_line(l, false).1)
        .collect();
    let lines = if lines.is_empty() {
        vec![Line::styled("No entries yet.", theme::muted())]
    } else {
        lines
    };
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

// -------------------------------------------------------------------- tables

fn draw_agents(frame: &mut Frame, app: &mut App, area: Rect) {
    let (list, side) = split_detail(area, 120);
    let rates = agent_rates(app);
    let agents = app.items(Tab::Agents);
    let rows: Vec<Vec<Line<'static>>> = agents
        .iter()
        .map(|a| {
            let name = s(&a["name"]);
            if a["invite"] == true {
                let left = a["expires_at"].as_i64().unwrap_or(0) - now();
                return vec![
                    cell(Line::from(vec![
                        dot("pending"),
                        Span::raw(" "),
                        Span::styled(name, theme::bold()),
                    ])),
                    cell("invited"),
                    cell(Span::styled("-", theme::muted())),
                    cell(Span::styled("-", theme::muted())),
                    cell(Span::styled(
                        format!("token valid {}", duration(left)),
                        theme::accent(),
                    )),
                    cell(Span::styled("-", theme::muted())),
                ];
            }
            let (state, label) = match a["status"].as_str() {
                Some("active") if a["online"] == true && a["configuration_ready"] == true => {
                    ("online", "online".to_string())
                }
                Some("active") if a["online"] == true => ("waiting", "syncing".to_string()),
                Some("active") => ("offline", "offline".to_string()),
                Some("pending") => ("pending", "enrolling".to_string()),
                Some(other) => ("off", other.to_string()),
                None => ("off", "?".to_string()),
            };
            let traffic = rates
                .get(a["id"].as_str().unwrap_or_default())
                .map(|(rx, tx)| format!("↓{} ↑{}", rate(*rx), rate(*tx)))
                .unwrap_or_default();
            vec![
                cell(Line::from(vec![
                    dot(state),
                    Span::raw(" "),
                    Span::styled(name, theme::bold()),
                ])),
                cell(label),
                cell(s(&a["tunnel_ipv4"])),
                cell(match a["last_handshake"].as_i64() {
                    Some(h) if h > 0 => ago(h),
                    _ => "never".into(),
                }),
                cell(traffic),
                cell(s(&a["rift_version"])),
            ]
        })
        .collect();
    table(
        frame,
        app,
        list,
        Tab::Agents,
        &list_title(app, Tab::Agents, "Agents"),
        &["NAME", "STATE", "TUNNEL", "HANDSHAKE", "TRAFFIC", "VERSION"],
        &[
            Constraint::Min(12),
            Constraint::Length(9),
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Length(34),
            Constraint::Length(10),
        ],
        &[5, 4, 3],
        rows,
        "No agents yet. Press a to invite the first one.",
    );
    let Some(side) = side else {
        return;
    };
    let Some(agent) = app.selected() else {
        return details(
            frame,
            side,
            "Details",
            vec![Line::styled("Nothing selected.", theme::muted())],
        );
    };
    if agent["invite"] == true {
        let name = s(&agent["name"]);
        let expires = agent["expires_at"].as_i64().unwrap_or(0);
        let enrollment = &app.overview()["enrollment"];
        let mut lines = vec![
            Line::styled("◷ Invitation open, not enrolled yet", theme::accent()),
            Line::raw(""),
            kv("Valid for", duration(expires - now())),
            kv("Until", clock_at(expires)),
            kv(
                "Enrollment",
                format!(
                    "{} on {}",
                    if enrollment["open"] == true {
                        "open"
                    } else {
                        "closed"
                    },
                    s(&enrollment["bind"])
                ),
            ),
            Line::raw(""),
            Line::styled(
                "On the agent host, run the deploy/join line shown when the invitation was created. The token is shown only then; t makes a new one (the old one stops working), c cancels the invitation.",
                theme::muted(),
            ),
        ];
        if enrollment["open"] != true {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "The enrollment port is closed: the agent cannot enroll (RIFT_ENROLLMENT).",
                theme::warn(),
            ));
        }
        return details(frame, side, &name, lines);
    }
    let name = s(&agent["name"]);
    let record = app.status()["snapshot"]["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["id"] == agent["id"])
        .cloned()
        .unwrap_or_default();
    let mut lines = vec![
        kv("ID", s(&agent["id"])),
        kv("Status", s(&agent["status"])),
        kv("IPv4", s(&agent["tunnel_ipv4"])),
        kv("IPv6", s(&agent["tunnel_ipv6"])),
        kv(
            "Name",
            match (agent["dns_name"].as_str(), agent["names"] == true) {
                (Some(dns), true) => format!("{dns} (on)"),
                (Some(dns), false) => format!("{dns} (off)"),
                _ => "-".into(),
            },
        ),
        kv("Version", s(&agent["rift_version"])),
    ];
    let limits = &record["limits"];
    if !limits.is_null() {
        let ports = match limits["ports"].as_array() {
            None => "any".to_string(),
            Some(list) if list.is_empty() => "none".into(),
            Some(list) => list
                .iter()
                .map(|p| {
                    let ports = range(&p["ports"]);
                    match p["protocol"].as_str() {
                        Some(proto) => format!("{ports}/{proto}"),
                        None => ports,
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
        };
        lines.push(kv("Ports", ports));
        let subnets: Vec<String> = limits["subnets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(s)
            .collect();
        lines.push(kv(
            "LANs",
            if subnets.is_empty() {
                "none".into()
            } else {
                subnets.join(", ")
            },
        ));
        lines.push(kv(
            "Exit",
            if limits["exit"] == true {
                "offered"
            } else {
                "not offered"
            },
        ));
    }
    if let Some(left) = app.invite_left(&name) {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("◷ Invitation open, {} left", duration(left)),
            theme::accent(),
        ));
    }
    if let Some(error) = agent["last_error"].as_str() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("✗ {error}"), theme::bad()));
    }
    // `rift host allow`: what the VPS host itself may reach on this agent.
    let host: Vec<&Value> = agent["host_grants"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    lines.push(Line::raw(""));
    if host.is_empty() {
        lines.push(Line::styled(
            "Server access: none (h allows ports)",
            theme::muted(),
        ));
    } else {
        lines.push(Line::styled("Server access", theme::accent()));
        if let Some((fine, note)) =
            crate::names::host_name_note(&agent, &app.overview()["host_names"])
        {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", "  Name"), theme::muted()),
                Span::styled(note, if fine { theme::ok() } else { theme::warn() }),
            ]));
        }
        for grant in host {
            let what = crate::output::vpn_access(&grant["access"]);
            lines.push(match grant["refused"].as_str() {
                Some(why) => Line::styled(format!("  ✗ {what}: refused, {why}"), theme::warn()),
                None => Line::raw(format!("  {what}")),
            });
        }
    }
    let forwards = app
        .all_forwards()
        .iter()
        .filter(|f| f["agent"] == agent["name"])
        .count();
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!("{forwards} forward(s)"),
        theme::muted(),
    ));
    details(frame, side, &name, lines);
}

fn forward_state(f: &Value) -> (&'static str, String) {
    if let Some(reason) = f["refused"].as_str() {
        ("refused", format!("refused: {reason}"))
    } else if f["enabled"] != true {
        ("off", "disabled".into())
    } else if f["pending"] == true {
        ("pending", "pending".into())
    } else {
        ("active", "active".into())
    }
}

fn draw_forwards(frame: &mut Frame, app: &mut App, area: Rect) {
    let forwards = app.items(Tab::Forwards);
    let agent_role = app.role == Role::Agent;
    // Narrow windows leave out columns; a strip below the table then shows the selected
    // forward in full.
    let (list, strip) = if area.width < 140 && area.height >= 16 {
        let [list, strip] =
            Layout::vertical([Constraint::Min(6), Constraint::Length(4)]).areas(area);
        (list, Some(strip))
    } else {
        (area, None)
    };
    let rows: Vec<Vec<Line<'static>>> = forwards
        .iter()
        .map(|f| {
            let (state, label) = forward_label(f, agent_role);
            vec![
                cell(Span::styled(s(&f["id"]), theme::muted())),
                cell(Span::styled(
                    if agent_role {
                        "this host".into()
                    } else {
                        s(&f["agent"])
                    },
                    theme::bold(),
                )),
                cell(format!(
                    "{}/{}",
                    listen(&f["listen_ip"], &f["listen_ports"]),
                    s(&f["protocol"])
                )),
                cell(forward_target(f)),
                cell(s(&f["mode"])),
                cell(forward_access(f)),
                cell(Line::from(vec![
                    dot(state),
                    Span::raw(" "),
                    Span::raw(label),
                ])),
            ]
        })
        .collect();
    table(
        frame,
        app,
        list,
        Tab::Forwards,
        &forwards_title(app),
        &["ID", "AGENT", "LISTEN", "TARGET", "MODE", "ACCESS", "STATE"],
        &[
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Length(52),
            Constraint::Length(24),
            Constraint::Length(11),
            Constraint::Length(40),
            Constraint::Min(10),
        ],
        &[5, 4],
        rows,
        if agent_role {
            "The server has published no ports of this host."
        } else {
            "No forwards yet. Press a to publish a port of an agent."
        },
    );
    let Some(strip) = strip else {
        return;
    };
    let lines = match app.selected() {
        Some(f) => {
            let (state, label) = forward_label(&f, agent_role);
            vec![
                Line::from(vec![
                    Span::styled(format!("#{} ", s(&f["id"])), theme::muted()),
                    Span::styled(
                        format!(
                            "{}/{} ",
                            listen(&f["listen_ip"], &f["listen_ports"]),
                            s(&f["protocol"])
                        ),
                        theme::bold(),
                    ),
                    Span::raw(format!(
                        "{} on {} · {} · ",
                        forward_target(&f),
                        if agent_role {
                            "this host".into()
                        } else {
                            s(&f["agent"])
                        },
                        s(&f["mode"])
                    )),
                    dot(state),
                    Span::raw(format!(" {label}")),
                ]),
                Line::from(vec![
                    Span::styled("access ", theme::muted()),
                    Span::raw(forward_access(&f)),
                ]),
            ]
        }
        None => vec![Line::styled("Nothing selected.", theme::muted())],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Selected forward")),
        strip,
    );
}

/// "Forwards · "nas 80" 2 of 11 · by port" when filtered or sorted.
fn forwards_title(app: &App) -> String {
    let mut title = "Forwards".to_string();
    if !app.forward_query.is_empty() || app.focus.is_some() {
        if let Some(agent) = &app.focus {
            title.push_str(&format!(" · agent {agent}"));
        }
        if !app.forward_query.is_empty() {
            title.push_str(&format!(" · \"{}\"", app.forward_filter));
        }
        title.push_str(&format!(
            " · {} of {}",
            app.items(Tab::Forwards).len(),
            app.all_forwards().len()
        ));
    }
    if app.forward_query.sort != crate::query::ForwardSort::Id {
        title.push_str(&format!(" · by {}", app.forward_query.sort.name()));
    }
    title
}

/// A list's title with its focus and filter: "VPN devices · agent nas · "phone" 1 of 4".
fn list_title(app: &App, tab: Tab, base: &str) -> String {
    let mut title = base.to_string();
    let focused = app.focus.as_ref().filter(|_| tab != Tab::Agents);
    let filter = app.filters.get(&tab);
    if let Some(agent) = focused {
        title.push_str(&format!(" · agent {agent}"));
    }
    if let Some(words) = filter {
        title.push_str(&format!(" · \"{words}\""));
    }
    if focused.is_some() || filter.is_some() {
        title.push_str(&format!(
            " · {} of {}",
            app.items(tab).len(),
            app.unfiltered(tab).len()
        ));
    }
    title
}

fn forward_label(f: &Value, agent_role: bool) -> (&'static str, String) {
    if !agent_role {
        return forward_state(f);
    }
    if f["enabled"] == true {
        ("active", "enabled".into())
    } else {
        ("off", "disabled".into())
    }
}

/// `→ 80`, with the target's address family where it changes (translated forwards).
fn forward_target(f: &Value) -> String {
    let family = match (f["mode"].as_str(), f["target_family"].as_str()) {
        (Some("translate"), Some(family)) => format!(" {family}"),
        _ => String::new(),
    };
    let exit = if f["purpose"] == "exit" {
        " (exit)"
    } else {
        ""
    };
    format!("→ {}{family}{exit}", range(&f["target_ports"]))
}

/// The ingress and the clients that may connect.
fn forward_access(f: &Value) -> String {
    let allow: Vec<String> = f["allow_from"]
        .as_array()
        .into_iter()
        .flatten()
        .map(s)
        .collect();
    if allow.is_empty() {
        format!("{}, every client", s(&f["ingress"]))
    } else {
        format!("{}, only {}", s(&f["ingress"]), allow.join(" "))
    }
}

fn draw_devices(frame: &mut Frame, app: &mut App, area: Rect) {
    let (list, side) = split_detail(area, 120);
    let devices = app.items(Tab::Devices);
    let rows: Vec<Vec<Line<'static>>> = devices
        .iter()
        .map(|d| {
            let handshake = d["last_handshake"].as_i64().unwrap_or(0);
            let connected = handshake > 0 && now() - handshake <= 180;
            let state = if d["enabled"] != true {
                "off"
            } else if connected {
                "online"
            } else {
                "idle"
            };
            let grants = d["grants"].as_array().map_or(0, Vec::len);
            let refused = d["grants"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|g| g["refused"].is_string())
                .count();
            let exits: Vec<String> = d["exits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| e["agent"].as_str().unwrap_or("server").to_string())
                .collect();
            vec![
                cell(Line::from(vec![
                    dot(state),
                    Span::raw(" "),
                    Span::styled(s(&d["name"]), theme::bold()),
                ])),
                cell(s(&d["ipv4"])),
                cell(if d["enabled"] == true {
                    "enabled"
                } else {
                    "disabled"
                }),
                cell(if handshake > 0 {
                    ago(handshake)
                } else {
                    "never".into()
                }),
                cell(if refused > 0 {
                    Line::from(vec![
                        Span::raw(format!("{grants} ")),
                        Span::styled(format!("✗{refused}"), theme::bad()),
                    ])
                } else {
                    Line::raw(grants.to_string())
                }),
                cell(if exits.is_empty() {
                    "-".into()
                } else {
                    exits.join(",")
                }),
                cell(if d["panel"] == true {
                    Span::styled("yes", theme::accent())
                } else {
                    Span::styled("no", theme::muted())
                }),
            ]
        })
        .collect();
    table(
        frame,
        app,
        list,
        Tab::Devices,
        &list_title(app, Tab::Devices, "VPN devices"),
        &[
            "NAME",
            "ADDRESS",
            "STATE",
            "HANDSHAKE",
            "GRANTS",
            "EXITS",
            "PANEL",
        ],
        &[
            Constraint::Min(12),
            Constraint::Length(15),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Min(6),
            Constraint::Length(5),
        ],
        &[6, 5, 4, 3],
        rows,
        "No VPN devices yet. Press a to add a phone or laptop.",
    );
    let Some(side) = side else {
        return;
    };
    let Some(device) = app.selected() else {
        return details(
            frame,
            side,
            "Details",
            vec![Line::styled("Nothing selected.", theme::muted())],
        );
    };
    let mut lines = vec![
        kv("IPv4", s(&device["ipv4"])),
        kv("IPv6", s(&device["ipv6"])),
        kv("Key", s(&device["public_key"])),
        kv(
            "Names",
            if device["names_off"] == true {
                "off".to_string()
            } else {
                let names: Vec<String> = device["names"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(s)
                    .collect();
                if names.is_empty() {
                    "on (none reachable)".into()
                } else {
                    names.join(", ")
                }
            },
        ),
        Line::raw(""),
        Line::styled("Access", theme::bold()),
    ];
    let grants: Vec<&Value> = device["grants"].as_array().into_iter().flatten().collect();
    if grants.is_empty() {
        lines.push(Line::styled(
            "  nothing yet (g grants access)",
            theme::muted(),
        ));
    }
    for grant in grants {
        let mut spans = vec![
            Span::raw("  "),
            Span::styled(s(&grant["agent"]), theme::accent()),
            Span::raw(format!(": {}", crate::output::vpn_access(&grant["access"]))),
        ];
        if let Some(reason) = grant["refused"].as_str() {
            spans.push(Span::styled(format!("  ✗ {reason}"), theme::bad()));
        }
        lines.push(Line::from(spans));
    }
    let exits: Vec<&Value> = device["exits"].as_array().into_iter().flatten().collect();
    if !exits.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Internet exits", theme::bold()));
        for exit in exits {
            let via = exit["agent"].as_str().unwrap_or("this server");
            let mut spans = vec![Span::raw(format!("  via {via}"))];
            if let Some(reason) = exit["reason"].as_str() {
                spans.push(Span::styled(format!("  ! {reason}"), theme::warn()));
            }
            lines.push(Line::from(spans));
        }
    }
    details(frame, side, &s(&device["name"]), lines);
}

fn draw_sites(frame: &mut Frame, app: &mut App, area: Rect) {
    let overview = app.overview().clone();
    let sites = app.items(Tab::Sites);
    let rows: Vec<Vec<Line<'static>>> = sites
        .iter()
        .map(|site| {
            let state = s(&site["forward"]);
            let allow: Vec<String> = site["allow_from"]
                .as_array()
                .into_iter()
                .flatten()
                .map(s)
                .collect();
            vec![
                cell(Span::styled(
                    format!("https://{}", s(&site["host"])),
                    theme::bold(),
                )),
                cell(s(&site["agent"])),
                cell(s(&site["target"])),
                cell(s(&site["proxy"])),
                cell(Line::from(vec![
                    dot(match state.as_str() {
                        "ok" | "active" => "active",
                        "missing" | "refused" => "bad",
                        _ => "warn",
                    }),
                    Span::raw(format!(" {state}")),
                ])),
                cell(if allow.is_empty() {
                    "everyone".into()
                } else {
                    allow.join(" ")
                }),
            ]
        })
        .collect();
    let empty = if overview["sites"]["available"] == false && overview["sites"]["queue"] == false {
        "Sites are managed by the host helper, which is not installed: run sudo sh deploy/install-cli on the server and recreate the container."
    } else {
        "No sites yet. Press a to publish a domain through the reverse proxy."
    };
    table(
        frame,
        app,
        area,
        Tab::Sites,
        &list_title(
            app,
            Tab::Sites,
            &if area.width >= 100 {
                sites_title(&overview)
            } else {
                format!("Sites · proxy {}", s(&overview["sites"]["proxy"]["name"]))
            },
        ),
        &["DOMAIN", "AGENT", "TARGET", "PROXY", "FORWARD", "ONLY FROM"],
        &[
            Constraint::Length(48),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
        &[5, 3],
        rows,
        empty,
    );
}

/// "Sites · proxy caddy (container rift-caddy)": what `rift proxy` shows.
fn sites_title(overview: &Value) -> String {
    let proxy = &overview["sites"]["proxy"];
    match proxy["name"].as_str() {
        None => "Sites".into(),
        Some("caddy") => match (
            proxy["caddy_container"].as_str(),
            proxy["caddy_sites_dir"].as_str(),
        ) {
            (Some(container), Some(dir)) => {
                format!("Sites · proxy caddy in container {container}, sites in {dir}")
            }
            (None, Some(dir)) => format!("Sites · proxy caddy on the host, sites in {dir}"),
            _ => "Sites · proxy caddy".into(),
        },
        Some(name) => format!("Sites · proxy {name}"),
    }
}

fn draw_backup(frame: &mut Frame, app: &mut App, area: Rect) {
    let [intro, list] = Layout::vertical([Constraint::Length(5), Constraint::Min(5)]).areas(area);
    let dir = crate::sites::FILES_DIR;
    let ready = app.overview()["sites"]["queue"] == true;
    let mut lines = vec![
        Line::from(vec![
            Span::styled("e", theme::accent().bold()),
            Span::raw(" saves the settings (no keys) and "),
            Span::styled("b", theme::accent().bold()),
            Span::raw(" a backup with every key, on the host in "),
            Span::styled(dir, theme::bold()),
            Span::raw("."),
        ]),
        Line::from(vec![
            Span::styled("i", theme::accent().bold()),
            Span::raw(" imports an export from there; copy a file into that directory to import it. Restoring a backup stops this server: "),
            Span::styled("sudo rift restore FILE", theme::bold()),
            Span::raw(" on the host."),
        ]),
    ];
    if !ready {
        lines.push(Line::styled(
            "The host helper is not installed: run sudo sh deploy/install-cli on the server and recreate the container.",
            theme::warn(),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("Export, backup and import")),
        intro,
    );
    let rows: Vec<Vec<Line<'static>>> = app
        .items(Tab::Backup)
        .iter()
        .map(|f| {
            let kind = match f["kind"].as_str() {
                Some("export") => Span::styled("settings", Style::new().fg(theme::SKY)),
                Some("backup") => Span::styled("backup, with keys", theme::warn()),
                _ => Span::styled("other", theme::muted()),
            };
            let age = now() - f["modified"].as_i64().unwrap_or(0);
            vec![
                cell(Span::styled(s(&f["name"]), theme::bold())),
                cell(kind),
                cell(bytes(f["size"].as_u64().unwrap_or(0))),
                cell(format!("{} ago", duration(age))),
            ]
        })
        .collect();
    table(
        frame,
        app,
        list,
        Tab::Backup,
        &format!("Files in {dir}"),
        &["FILE", "KIND", "SIZE", "SAVED"],
        &[
            Constraint::Min(30),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(16),
        ],
        &[2, 3],
        rows,
        "No files yet. e exports the settings, b saves a backup.",
    );
}

fn draw_bans(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Vec<Line<'static>>> = app
        .items(Tab::Bans)
        .iter()
        .map(|b| {
            let left = b["expires_at"].as_i64().unwrap_or(0) - now();
            vec![
                cell(Span::styled(s(&b["id"]), theme::muted())),
                cell(s(&b["agent"])),
                cell(s(&b["forward_id"])),
                cell(Span::styled(s(&b["ip"]), theme::bold())),
                cell(format!("in {}", duration(left))),
            ]
        })
        .collect();
    table(
        frame,
        app,
        area,
        Tab::Bans,
        &list_title(app, Tab::Bans, "Bans"),
        &["ID", "AGENT", "FORWARD", "ADDRESS", "EXPIRES"],
        &[
            Constraint::Length(5),
            Constraint::Min(12),
            Constraint::Length(8),
            Constraint::Min(18),
            Constraint::Length(14),
        ],
        &[0],
        rows,
        "No active bans. Bans block client addresses on translated forwards.",
    );
}

fn draw_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    let overview = app.overview().clone();
    let panel_status = &overview["panel"];
    if panel_status["enabled"] != true {
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled("The web panel is off.", theme::bold()),
                Line::raw(""),
                Line::styled(
                    "Turn it on with RIFT_WEBPANEL=true in the server .env (or sudo sh deploy/setup-server)",
                    theme::muted(),
                ),
                Line::styled("and recreate the container: docker compose up -d --force-recreate", theme::muted()),
            ])
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(panel("Web panel")),
            area,
        );
        return;
    }
    let [left, right] = Layout::horizontal([Constraint::Ratio(1, 2); 2]).areas(area);
    let running = panel_status["error"].is_null();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!("{:<12}", "Status"), theme::muted()),
            if !running {
                Span::styled("on, but not running", theme::bad().bold())
            } else if panel_status["listening"]
                .as_array()
                .is_some_and(|l| !l.is_empty())
            {
                Span::styled("running", theme::ok().bold())
            } else {
                Span::styled("starting", theme::warn())
            },
        ]),
        kv("Listens", s(&panel_status["access"])),
        kv("Changes", s(&panel_status["control"])),
        kv("Port", s(&panel_status["port"])),
    ];
    if let Some(error) = panel_status["error"].as_str() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("✗ {error}"), theme::bad()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Addresses", theme::bold()));
    for url in panel_status["urls"].as_array().into_iter().flatten() {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                s(&url["url"]),
                theme::accent().add_modifier(Modifier::UNDERLINED),
            ),
            Span::styled(format!("  {}", s(&url["via"])), theme::muted()),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Password"), theme::muted()),
        match &app.password {
            Some(password) => Span::styled(password.clone(), theme::warn().bold()),
            None if panel_status["password"] == "RIFT_WEBPANEL_PASSWORD" => Span::styled(
                "•••••••••••• (RIFT_WEBPANEL_PASSWORD; p shows it)",
                theme::muted(),
            ),
            None => Span::styled("•••••••••••• (generated; p shows it)", theme::muted()),
        },
    ]));
    let two_factor = &overview["two_factor"];
    lines.push(Line::from(vec![
        Span::styled(format!("{:<12}", "Two-factor"), theme::muted()),
        if two_factor["enabled"] == true {
            Span::styled("on", theme::ok().bold())
        } else {
            Span::styled("off", theme::warn().bold())
        },
        Span::styled(
            format!("  (mode {})", s(&two_factor["mode"])),
            theme::muted(),
        ),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Web panel")),
        left,
    );
    let mut lines = Vec::new();
    for device in panel_status["devices"].as_array().into_iter().flatten() {
        lines.push(Line::from(vec![
            dot(if device["enabled"] == true {
                "active"
            } else {
                "off"
            }),
            Span::raw(" "),
            Span::styled(format!("{:<16}", s(&device["name"])), theme::bold()),
            Span::styled(s(&device["ipv4"]), theme::muted()),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::styled(
            "No VPN device may open the panel. g grants one.",
            theme::muted(),
        ));
    }
    let allow: Vec<String> = panel_status["allow"]
        .as_array()
        .into_iter()
        .flatten()
        .map(s)
        .collect();
    if !allow.is_empty() {
        lines.push(Line::raw(""));
        lines.push(kv("Also allowed", allow.join(", ")));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Devices with panel access")),
        right,
    );
}

fn draw_logs(frame: &mut Frame, app: &mut App, area: Rect) {
    let levels = [
        "all levels",
        "info and above",
        "warnings and errors",
        "errors only",
    ];
    let title = format!(
        "Log · {} · {}{}",
        if app.logs.follow {
            "following"
        } else {
            "paused"
        },
        levels[app.logs.level as usize],
        if app.logs.filter.is_empty() {
            String::new()
        } else {
            format!(" · \"{}\"", app.logs.filter)
        }
    );
    let block = panel(&title);
    let inner = block.inner(area);
    let filter = app.logs.filter.to_lowercase();
    let logs = app.snapshot.as_ref().map(|s| &s.logs[..]).unwrap_or(&[]);
    let lines: Vec<Line> = logs
        .iter()
        .filter(|l| filter.is_empty() || l.to_lowercase().contains(&filter))
        .map(|l| log_line(l, true))
        .filter(|(level, _)| *level >= app.logs.level)
        .map(|(_, line)| line)
        .collect();
    let height = inner.height as usize;
    let total = lines.len();
    let max_scroll = total.saturating_sub(height);
    if app.logs.scroll > max_scroll {
        app.logs.scroll = max_scroll;
    }
    let end = total - app.logs.scroll;
    let start = end.saturating_sub(height);
    let shown: Vec<Line> = if lines.is_empty() {
        vec![Line::styled(
            "No log entries (Docker keeps older ones: docker logs rift-server).",
            theme::muted(),
        )]
    } else {
        lines[start..end].to_vec()
    };
    frame.render_widget(Paragraph::new(shown).block(block), area);
    app.hits.push((inner, Hit::LogScroll));
    if total > height {
        let mut state = ScrollbarState::new(max_scroll).position(max_scroll - app.logs.scroll);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(theme::accent())
                .track_style(theme::border()),
            area.inner(Margin::new(0, 1)),
            &mut state,
        );
    }
}

/// One structured log line, coloured, with its level (0 debug/trace .. 3 error).
fn log_line(raw: &str, full: bool) -> (u8, Line<'static>) {
    let Ok(entry) = serde_json::from_str::<Value>(raw) else {
        return (1, Line::raw(raw.to_string()));
    };
    let level = entry["level"].as_str().unwrap_or("INFO").to_string();
    let (rank, style) = match level.as_str() {
        "ERROR" => (3, theme::bad().bold()),
        "WARN" => (2, theme::warn().bold()),
        "INFO" => (1, Style::new().fg(theme::SKY)),
        _ => (0, theme::muted()),
    };
    let time = entry["timestamp"]
        .as_str()
        .and_then(|t| t.split('T').nth(1))
        .map(|t| t.chars().take(8).collect::<String>())
        .unwrap_or_default();
    let fields = &entry["fields"];
    let message = fields["message"].as_str().unwrap_or_default().to_string();
    let mut spans = vec![
        Span::styled(format!("{time} "), theme::muted()),
        Span::styled(format!("{level:<5} "), style),
        Span::raw(message),
    ];
    if let Some(map) = fields.as_object() {
        for (key, value) in map.iter().filter(|(k, _)| *k != "message") {
            spans.push(Span::styled(format!("  {key}="), theme::muted()));
            spans.push(Span::styled(s(value), Style::new().fg(theme::ACCENT)));
        }
    }
    if full {
        if let Some(target) = entry["target"].as_str() {
            spans.push(Span::styled(
                format!("  ({target})"),
                theme::muted().italic(),
            ));
        }
    }
    (rank, Line::from(spans))
}

fn draw_health(frame: &mut Frame, app: &mut App, area: Rect) {
    let [summary, list] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);
    let checks = app.items(Tab::Health);
    let failures = checks.iter().filter(|c| c["status"] == "fail").count();
    let warnings = checks
        .iter()
        .filter(|c| c["status"] != "fail" && c["status"] != "ok")
        .count();
    let line = match &app.health {
        _ if app.health_loading => Line::styled(
            format!("{} Running the checks…", SPINNER[app.frame % SPINNER.len()]),
            theme::accent(),
        ),
        None => Line::styled("Press r to run the checks.", theme::muted()),
        Some(Err(e)) => Line::styled(format!("✗ {e}"), theme::bad()),
        Some(Ok(_)) => match (failures, warnings) {
            (0, 0) => Line::styled("✓ Everything looks fine.", theme::ok().bold()),
            (0, w) => Line::styled(
                format!("! {w} warning(s); RIFT works, but see below."),
                theme::warn().bold(),
            ),
            (f, _) => Line::styled(format!("✗ {f} problem(s) to fix."), theme::bad().bold()),
        },
    };
    frame.render_widget(
        Paragraph::new(line).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(theme::border())
                .padding(Padding::horizontal(1)),
        ),
        summary,
    );
    let rows: Vec<Vec<Line<'static>>> = checks
        .iter()
        .map(|c| {
            let mark = match c["status"].as_str() {
                Some("ok") => Span::styled("✓", theme::ok()),
                Some("fail") => Span::styled("✗", theme::bad().bold()),
                _ => Span::styled("!", theme::warn().bold()),
            };
            vec![
                cell(mark),
                cell(Span::styled(s(&c["check"]), theme::bold())),
                cell(s(&c["detail"])),
            ]
        })
        .collect();
    table(
        frame,
        app,
        list,
        Tab::Health,
        "Checks (rift doctor)",
        &["", "CHECK", "DETAIL"],
        &[
            Constraint::Length(1),
            Constraint::Length(28),
            Constraint::Min(20),
        ],
        &[],
        rows,
        "No results yet.",
    );
}

// -------------------------------------------------------------------- modals

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

fn popup_block(title: &str, color: ratatui::style::Color) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(title.to_string(), Style::new().fg(color).bold()),
            Span::raw(" "),
        ]))
        .style(theme::popup())
        .padding(Padding::new(2, 2, 1, 0))
}

/// Buttons right-aligned on one row; returns nothing, records the hits.
fn buttons(frame: &mut Frame, app: &mut App, area: Rect, list: &[(&str, Style, Hit)]) {
    let total: u16 = list
        .iter()
        .map(|(l, _, _)| l.chars().count() as u16 + 6)
        .sum();
    let mut x = area.x + area.width.saturating_sub(total);
    for (label, style, hit) in list {
        let text = format!("  {label}  ");
        let w = text.chars().count() as u16;
        let rect = Rect::new(x, area.y, w, 1);
        frame.render_widget(Span::styled(text, *style), rect);
        app.hits.push((rect, *hit));
        x += w + 2;
    }
}

fn draw_modal(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(modal) = app.modals.pop() else {
        return;
    };
    let modal = draw_one(frame, app, area, modal);
    app.modals.push(modal);
}

fn draw_one(frame: &mut Frame, app: &mut App, area: Rect, mut modal: Modal) -> Modal {
    match &mut modal {
        Modal::Form { form, .. } => {
            let width = 84.min(area.width.saturating_sub(4));
            let inner_width = width.saturating_sub(6);
            let height = form.height(inner_width) + 4;
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block(
                &form.title,
                if form.danger {
                    theme::BAD
                } else {
                    theme::ACCENT
                },
            )
            .padding(Padding::new(2, 2, 1, 1));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            form.render(frame, inner);
            app.hits.push((rect, Hit::ModalArea));
        }
        Modal::Confirm {
            title,
            text,
            danger,
            yes,
            ..
        } => {
            let width = 64.min(area.width.saturating_sub(4));
            let height = wrapped_lines(text, width.saturating_sub(6)) + 5;
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let color = if *danger { theme::BAD } else { theme::ACCENT };
            let block = popup_block(title, color);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            frame.render_widget(
                Paragraph::new(text.clone()).wrap(Wrap { trim: false }),
                inner,
            );
            app.hits.push((rect, Hit::ModalArea));
            let yes_style = match (*yes, *danger) {
                (true, true) => theme::button_danger(),
                (true, false) => theme::button_focus(),
                (false, true) => theme::button().fg(theme::BAD),
                (false, false) => theme::button(),
            };
            let no_style = if *yes {
                theme::button()
            } else {
                theme::button_focus()
            };
            let row = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            );
            buttons(
                frame,
                app,
                row,
                &[
                    ("Yes (y)", yes_style, Hit::Yes),
                    ("No (n)", no_style, Hit::No),
                ],
            );
        }
        Modal::Menu {
            title,
            items,
            index,
        } => {
            let label_width = items
                .iter()
                .map(|i| i.label.chars().count() + i.hint.chars().count() + 6)
                .max()
                .unwrap_or(20)
                .max(title.chars().count() + 6) as u16;
            let width = (label_width + 6).clamp(36, 90);
            let height = items.len() as u16 + 3;
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block(title, theme::ACCENT).padding(Padding::new(1, 1, 1, 0));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            app.hits.push((rect, Hit::ModalArea));
            let skip = (*index + 1).saturating_sub(inner.height as usize);
            for (row, (i, item)) in items.iter().enumerate().skip(skip).enumerate() {
                if row as u16 >= inner.height {
                    break;
                }
                let y = inner.y + row as u16;
                let selected = i == *index;
                let disabled = matches!(item.what, MenuWhat::Disabled);
                let style = if disabled {
                    theme::muted()
                } else if selected {
                    theme::selected().fg(theme::TEXT)
                } else {
                    Style::new()
                };
                let rect = Rect::new(inner.x, y, inner.width, 1);
                let hint_width = item.hint.chars().count() as u16;
                frame.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(if selected { " ▸ " } else { "   " }, theme::accent()),
                        Span::styled(item.label.clone(), style),
                    ]))
                    .style(if selected {
                        theme::selected()
                    } else {
                        Style::new()
                    }),
                    rect,
                );
                if hint_width > 0 {
                    frame.render_widget(
                        Span::styled(
                            item.hint.clone(),
                            if selected {
                                theme::accent().bg(theme::SELECTED)
                            } else {
                                theme::muted()
                            },
                        ),
                        Rect::new(
                            inner.x + inner.width.saturating_sub(hint_width + 1),
                            y,
                            hint_width,
                            1,
                        ),
                    );
                }
                app.hits.push((rect, Hit::MenuItem(i)));
            }
        }
        Modal::Text {
            title,
            lines,
            scroll,
            copy,
        } => {
            let longest = lines.iter().map(Line::width).max().unwrap_or(20) as u16;
            let width = (longest + 8)
                .clamp(50, 110)
                .min(area.width.saturating_sub(4));
            let wrapped: u16 = lines
                .iter()
                .map(|l| wrapped_lines(&l.to_string(), width.saturating_sub(6)))
                .sum();
            let height = (wrapped + 5).min(area.height.saturating_sub(2));
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block(title, theme::ACCENT);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            app.hits.push((rect, Hit::ModalArea));
            let body = Rect::new(
                inner.x,
                inner.y,
                inner.width,
                inner.height.saturating_sub(2),
            );
            let max = wrapped.saturating_sub(body.height);
            *scroll = (*scroll).min(max);
            frame.render_widget(
                Paragraph::new(Text::from(lines.clone()))
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0)),
                body,
            );
            let row = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            );
            if max > 0 {
                frame.render_widget(
                    Span::styled(format!("↑↓ scroll {}/{}", *scroll, max), theme::muted()),
                    row,
                );
            }
            let mut list: Vec<(&str, Style, Hit)> = copy
                .iter()
                .enumerate()
                .map(|(i, c)| (c.label, theme::button(), Hit::Copy(i)))
                .collect();
            if !copy.is_empty() && max == 0 {
                frame.render_widget(Span::styled("Copy:", theme::muted()), row);
            }
            list.push(("Close", theme::button_focus(), Hit::Close));
            buttons(frame, app, row, &list);
        }
        Modal::Qr {
            title,
            qr,
            text,
            note,
            show_text,
            scroll,
        } => {
            let qr_lines: Vec<&str> = qr.lines().collect();
            let qr_width = qr_lines
                .iter()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0) as u16;
            let qr_height = qr_lines.len() as u16;
            let fits = qr_width + 4 <= area.width && qr_height + 4 <= area.height;
            // Too small for the dialog: the code alone on the whole screen, one line below it.
            let bare = !fits && qr_width <= area.width && qr_height < area.height;
            if bare && !*show_text {
                frame.render_widget(Clear, area);
                app.hits.push((area, Hit::ModalArea));
                let top = area.y + (area.height - 1 - qr_height) / 2;
                let x = area.x + (area.width - qr_width) / 2;
                for (i, line) in qr_lines.iter().enumerate() {
                    frame.render_widget(
                        Span::styled(
                            line.to_string(),
                            Style::new()
                                .fg(ratatui::style::Color::Black)
                                .bg(ratatui::style::Color::White),
                        ),
                        Rect::new(x, top + i as u16, qr_width, 1),
                    );
                }
                let row = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
                frame.render_widget(
                    Span::styled(format!(" {title} "), theme::accent().bold()),
                    row,
                );
                buttons(
                    frame,
                    app,
                    row,
                    &[
                        ("Text (t)", theme::button(), Hit::QrToggle),
                        ("Copy (y)", theme::button(), Hit::Copy(0)),
                        ("Close", theme::button_focus(), Hit::Close),
                    ],
                );
                return modal;
            }
            let showing_text = *show_text || !fits;
            let content: Vec<Line> = if showing_text {
                text.lines().map(|l| Line::raw(l.to_string())).collect()
            } else {
                // Dark modules are the drawn blocks: black on white scans in any terminal theme.
                qr_lines
                    .iter()
                    .map(|l| {
                        Line::styled(
                            l.to_string(),
                            Style::new()
                                .fg(ratatui::style::Color::Black)
                                .bg(ratatui::style::Color::White),
                        )
                    })
                    .collect()
            };
            let content_width = content.iter().map(Line::width).max().unwrap_or(20) as u16;
            let width = (content_width + 4)
                .max(note.chars().count() as u16 + 4)
                .max(56)
                .min(area.width);
            let height = (content.len() as u16 + 4 + u16::from(showing_text)).min(area.height);
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block(title, theme::ACCENT).padding(Padding::new(1, 1, 0, 0));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            app.hits.push((rect, Hit::ModalArea));
            let body = Rect::new(
                inner.x,
                inner.y,
                inner.width,
                inner.height.saturating_sub(2),
            );
            let max = (content.len() as u16).saturating_sub(body.height);
            *scroll = (*scroll).min(max);
            let paragraph = Paragraph::new(content).scroll((*scroll, 0));
            frame.render_widget(
                if showing_text {
                    paragraph.wrap(Wrap { trim: false })
                } else {
                    paragraph.alignment(Alignment::Center)
                },
                body,
            );
            let note_row = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(2),
                inner.width,
                1,
            );
            let note_text = if !fits && !*show_text {
                "The window is too small for the QR code; enlarge it to scan.".to_string()
            } else {
                note.clone()
            };
            frame.render_widget(
                Paragraph::new(Span::styled(note_text, theme::warn())).alignment(Alignment::Center),
                note_row,
            );
            let row = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            );
            buttons(
                frame,
                app,
                row,
                &[
                    (
                        if showing_text {
                            "QR code (t)"
                        } else {
                            "Text (t)"
                        },
                        theme::button(),
                        Hit::QrToggle,
                    ),
                    ("Copy (y)", theme::button(), Hit::Copy(0)),
                    ("Close", theme::button_focus(), Hit::Close),
                ],
            );
        }
        Modal::Site {
            title,
            started,
            result,
            scroll,
            ..
        } => {
            let (text, color) = match result {
                None => (
                    format!(
                        "{} Waiting for the host service… {} s",
                        SPINNER[app.frame % SPINNER.len()],
                        started.elapsed().as_secs()
                    ),
                    theme::ACCENT,
                ),
                Some((true, message)) => (format!("✓ Done.\n\n{message}"), theme::OK),
                Some((false, message)) => (
                    format!("✗ The host refused or failed:\n\n{message}"),
                    theme::BAD,
                ),
            };
            let width = 90.min(area.width.saturating_sub(4));
            let rows = wrapped_lines(&text, width.saturating_sub(6));
            let height = (rows + 5).min(area.height.saturating_sub(2));
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block(title, color);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            app.hits.push((rect, Hit::ModalArea));
            let body = Rect::new(
                inner.x,
                inner.y,
                inner.width,
                inner.height.saturating_sub(2),
            );
            let max = rows.saturating_sub(body.height);
            *scroll = (*scroll).min(max);
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0)),
                body,
            );
            if max > 0 {
                frame.render_widget(
                    Span::styled(format!("↑↓ scroll {}/{max}", *scroll), theme::muted()),
                    Rect::new(inner.x, inner.y + inner.height.saturating_sub(1), 24, 1),
                );
            }
            let row = Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            );
            buttons(
                frame,
                app,
                row,
                &[(
                    if result.is_some() { "Close" } else { "Hide" },
                    theme::button_focus(),
                    Hit::Close,
                )],
            );
        }
        Modal::Help { scroll } => {
            let lines = help(app);
            let width = 78.min(area.width.saturating_sub(4));
            let height = (lines.len() as u16 + 4).min(area.height.saturating_sub(2));
            let rect = popup(area, width, height);
            frame.render_widget(Clear, rect);
            let block = popup_block("Keys and mouse", theme::ACCENT);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            app.hits.push((rect, Hit::ModalArea));
            let max = (lines.len() as u16).saturating_sub(inner.height);
            *scroll = (*scroll).min(max);
            frame.render_widget(Paragraph::new(lines).scroll((*scroll, 0)), inner);
        }
    }
    modal
}

fn help(app: &App) -> Vec<Line<'static>> {
    let key = |k: &str, text: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<14}"), theme::accent().bold()),
            Span::raw(text.to_string()),
        ])
    };
    let mut lines = vec![
        Line::styled("Everywhere", theme::bold()),
        key(
            "1-9 0 Tab ←→",
            "switch tabs (0 is the tenth; or click a tab)",
        ),
        key("↑↓ j k PgUp", "move in tables, scroll the log"),
        key(
            "Enter",
            "actions of the selected row (or right/double click)",
        ),
        key(":", "run any rift command, e.g. :list forwards"),
        key("R", "reconcile: apply the desired state again"),
        key(
            "F",
            "focus on one agent: its forwards, devices, sites, bans",
        ),
        key("/  s", "filter a list; sort the forwards"),
        key("F5  Ctrl-L", "refresh now (also every 3 s by itself)"),
        key("q  Ctrl-C", "quit; Esc closes dialogs"),
        Line::raw(""),
        Line::styled("Dialogs", theme::bold()),
        key("Tab ↑↓", "next / previous field"),
        key("← →  Space", "change a choice, tick a box"),
        key("Enter", "submit (or click the button)"),
        key(
            "y  1 2 3",
            "copy a configuration, or what an invitation's buttons say (OSC 52)",
        ),
        Line::raw(""),
        Line::styled("Mouse", theme::bold()),
        Line::raw(" Click tabs, rows, buttons and fields; scroll with the wheel."),
        Line::raw(" To select text for copying, hold Shift while dragging."),
        Line::raw(""),
        Line::styled("This tab", theme::bold()),
    ];
    let actions = app.actions();
    if actions.is_empty() {
        lines.push(Line::styled(" no actions here", theme::muted()));
    }
    for (k, label, _) in actions {
        lines.push(key(k, &label));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " The command line `rift …` keeps working as before; RIFT_TUI=false turns this UI off.",
        theme::muted(),
    ));
    lines
}

// -------------------------------------------------------------------- formatting

fn clock() -> String {
    let secs = now().rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// A Unix time as `HH:MM UTC` (today) or `YYYY-MM-DD HH:MM UTC`.
fn clock_at(timestamp: i64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp.max(0) as u64);
    let text = humantime::format_rfc3339_seconds(at).to_string();
    let (date, time) = text.split_once('T').unwrap_or((&text, ""));
    let today = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    if today.starts_with(date) {
        format!("{} UTC", &time[..5.min(time.len())])
    } else {
        format!("{date} {} UTC", &time[..5.min(time.len())])
    }
}

fn ago(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "never".into();
    }
    format!("{} ago", duration(now() - timestamp))
}

fn duration(seconds: i64) -> String {
    let s = seconds.max(0);
    match s {
        0..=59 => format!("{s} s"),
        60..=3599 => format!("{} min", s / 60),
        3600..=86_399 => format!("{} h {} min", s / 3600, s / 60 % 60),
        _ => format!("{} d {} h", s / 86_400, s / 3600 % 24),
    }
}

fn rate(bytes_per_second: u64) -> String {
    format!("{}/s", bytes(bytes_per_second))
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_read_well() {
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_500), "1.5 KB");
        assert_eq!(bytes(2_000_000), "2.0 MB");
        assert_eq!(duration(5), "5 s");
        assert_eq!(duration(125), "2 min");
        assert_eq!(duration(3_700), "1 h 1 min");
        assert_eq!(duration(90_000), "1 d 1 h");
        assert_eq!(duration(-3), "0 s");
        assert_eq!(ago(0), "never");
    }

    #[test]
    fn log_lines_keep_level_message_and_fields() {
        let raw = r#"{"timestamp":"2026-11-19T10:11:12.345Z","level":"WARN","fields":{"message":"agent offline","agent":"node1"},"target":"rift::daemon"}"#;
        let (level, line) = log_line(raw, true);
        assert_eq!(level, 2);
        let text = line.to_string();
        assert!(text.starts_with("10:11:12 WARN  agent offline"), "{text}");
        assert!(
            text.contains("agent=node1") && text.contains("rift::daemon"),
            "{text}"
        );
        let (level, line) = log_line("plain text", false);
        assert_eq!((level, line.to_string()), (1, "plain text".to_string()));
    }
}
