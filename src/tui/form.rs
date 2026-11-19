//! Dialogs of the terminal UI: forms with text fields, choices and check boxes, operated by
//! keyboard or mouse. A form only collects values; what happens on submit is up to `app`.

use super::theme;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::crossterm;
use ratatui::{
    layout::{Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};

#[derive(Clone, Debug)]
pub enum Kind {
    Text {
        value: String,
        /// Cursor position in characters.
        cursor: usize,
        placeholder: String,
        secret: bool,
    },
    /// (value, label) pairs.
    Select {
        options: Vec<(String, String)>,
        index: usize,
    },
    Check {
        on: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Field {
    pub key: &'static str,
    pub label: String,
    pub kind: Kind,
    pub hint: Option<String>,
}
impl Field {
    pub fn text(key: &'static str, label: &str, value: &str, placeholder: &str) -> Self {
        Self {
            key,
            label: label.into(),
            kind: Kind::Text {
                value: value.into(),
                cursor: value.chars().count(),
                placeholder: placeholder.into(),
                secret: false,
            },
            hint: None,
        }
    }
    pub fn select(key: &'static str, label: &str, options: Vec<(String, String)>) -> Self {
        Self {
            key,
            label: label.into(),
            kind: Kind::Select { options, index: 0 },
            hint: None,
        }
    }
    pub fn check(key: &'static str, label: &str, on: bool) -> Self {
        Self {
            key,
            label: label.into(),
            kind: Kind::Check { on },
            hint: None,
        }
    }
    pub fn hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.into());
        self
    }
    /// Selects the option with this value, if there is one.
    pub fn selected(mut self, value: &str) -> Self {
        if let Kind::Select { options, index } = &mut self.kind {
            if let Some(i) = options.iter().position(|(v, _)| v == value) {
                *index = i;
            }
        }
        self
    }
}

/// What a mouse click in a form hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormHit {
    Field(usize),
    /// The left or right arrow of a choice.
    Prev(usize),
    Next(usize),
    Submit,
    Cancel,
}

pub enum Outcome {
    None,
    Submit,
    Cancel,
}

#[derive(Clone, Debug)]
pub struct Form {
    pub title: String,
    pub intro: Vec<String>,
    pub fields: Vec<Field>,
    /// Index into fields; `fields.len()` is the submit button, `+1` the cancel button.
    pub focus: usize,
    pub submit: String,
    pub danger: bool,
    pub error: Option<String>,
    pub hits: Vec<(Rect, FormHit)>,
}

impl Form {
    pub fn new(title: &str, submit: &str, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            intro: Vec::new(),
            fields,
            focus: 0,
            submit: submit.into(),
            danger: false,
            error: None,
            hits: Vec::new(),
        }
    }
    pub fn intro(mut self, text: &str) -> Self {
        self.intro.push(text.into());
        self
    }

    pub fn text(&self, key: &str) -> String {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .and_then(|f| match &f.kind {
                Kind::Text { value, .. } => Some(value.trim().to_string()),
                Kind::Select { options, index } => options.get(*index).map(|o| o.0.clone()),
                Kind::Check { on } => Some(on.to_string()),
            })
            .unwrap_or_default()
    }
    pub fn on(&self, key: &str) -> bool {
        self.fields
            .iter()
            .any(|f| f.key == key && matches!(f.kind, Kind::Check { on: true }))
    }

    fn buttons(&self) -> usize {
        self.fields.len()
    }

    pub fn key(&mut self, key: KeyEvent) -> Outcome {
        let n = self.fields.len() + 2;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => return Outcome::Cancel,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + n - 1) % n,
            // Enter submits from every field; Space ticks a box.
            KeyCode::Enter => {
                if self.focus == self.buttons() + 1 {
                    return Outcome::Cancel;
                }
                return Outcome::Submit;
            }
            _ => {}
        }
        let Some(field) = self.fields.get_mut(self.focus) else {
            match key.code {
                KeyCode::Left | KeyCode::Right => {
                    self.focus = if self.focus == self.buttons() {
                        self.buttons() + 1
                    } else {
                        self.buttons()
                    }
                }
                KeyCode::Char(' ') if self.focus == self.buttons() => return Outcome::Submit,
                KeyCode::Char(' ') => return Outcome::Cancel,
                _ => {}
            }
            return Outcome::None;
        };
        match &mut field.kind {
            Kind::Text { value, cursor, .. } => {
                let len = value.chars().count();
                match key.code {
                    KeyCode::Char('u') if ctrl => {
                        value.clear();
                        *cursor = 0;
                    }
                    KeyCode::Char('a') if ctrl => *cursor = 0,
                    KeyCode::Char('e') if ctrl => *cursor = len,
                    KeyCode::Char(c) if !ctrl => {
                        let at = byte_index(value, *cursor);
                        value.insert(at, c);
                        *cursor += 1;
                    }
                    KeyCode::Backspace if *cursor > 0 => {
                        let at = byte_index(value, *cursor - 1);
                        value.remove(at);
                        *cursor -= 1;
                    }
                    KeyCode::Delete if *cursor < len => {
                        let at = byte_index(value, *cursor);
                        value.remove(at);
                    }
                    KeyCode::Left => *cursor = cursor.saturating_sub(1),
                    KeyCode::Right => *cursor = (*cursor + 1).min(len),
                    KeyCode::Home => *cursor = 0,
                    KeyCode::End => *cursor = len,
                    _ => {}
                }
            }
            Kind::Select { options, index } => {
                let n = options.len().max(1);
                match key.code {
                    KeyCode::Left | KeyCode::Char('h') => *index = (*index + n - 1) % n,
                    KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') => {
                        *index = (*index + 1) % n
                    }
                    _ => {}
                }
            }
            Kind::Check { on } => {
                if matches!(
                    key.code,
                    KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                ) {
                    *on = !*on;
                }
            }
        }
        Outcome::None
    }

    /// Text pasted into the focused text field.
    pub fn paste(&mut self, text: &str) {
        if let Some(Field {
            kind: Kind::Text { value, cursor, .. },
            ..
        }) = self.fields.get_mut(self.focus)
        {
            for c in text.chars().filter(|c| !c.is_control()) {
                let at = byte_index(value, *cursor);
                value.insert(at, c);
                *cursor += 1;
            }
        }
    }

    pub fn click(&mut self, position: Position) -> Outcome {
        let Some(hit) = self
            .hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(position))
            .map(|(_, h)| *h)
        else {
            return Outcome::None;
        };
        match hit {
            FormHit::Submit => return Outcome::Submit,
            FormHit::Cancel => return Outcome::Cancel,
            FormHit::Field(i) | FormHit::Prev(i) | FormHit::Next(i) => {
                self.focus = i;
                let Some(field) = self.fields.get_mut(i) else {
                    return Outcome::None;
                };
                match &mut field.kind {
                    Kind::Check { on } => *on = !*on,
                    Kind::Select { options, index } => {
                        let n = options.len().max(1);
                        *index = if hit == FormHit::Prev(i) {
                            (*index + n - 1) % n
                        } else {
                            (*index + 1) % n
                        };
                    }
                    Kind::Text { value, cursor, .. } => *cursor = value.chars().count(),
                }
            }
        }
        Outcome::None
    }

    /// The rows this form needs inside its border.
    pub fn height(&self, width: u16) -> u16 {
        let intro: u16 = self.intro.iter().map(|t| wrapped_lines(t, width)).sum();
        let fields: u16 = self
            .fields
            .iter()
            .map(|f| 1 + u16::from(f.hint.is_some()))
            .sum();
        let error = self
            .error
            .as_deref()
            .map_or(0, |e| wrapped_lines(&format!("✗ {e}"), width) + 1);
        intro + u16::from(!self.intro.is_empty()) + fields + error + 2
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.hits.clear();
        let label_width = self
            .fields
            .iter()
            .map(|f| f.label.chars().count())
            .max()
            .unwrap_or(0)
            .min(28) as u16
            + 4;
        let mut y = area.y;
        let bottom = area.y + area.height;
        for text in &self.intro {
            let h = wrapped_lines(text, area.width);
            frame.render_widget(
                Paragraph::new(text.as_str())
                    .style(theme::muted())
                    .wrap(Wrap { trim: false }),
                Rect::new(area.x, y, area.width, h.min(bottom.saturating_sub(y))),
            );
            y += h;
        }
        if !self.intro.is_empty() {
            y += 1;
        }
        for (i, field) in self.fields.iter().enumerate() {
            if y >= bottom {
                break;
            }
            let focused = self.focus == i;
            let label_style = if focused {
                theme::accent().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            };
            let marker = if focused { "▸ " } else { "  " };
            frame.render_widget(
                Line::from(vec![
                    Span::styled(marker, theme::accent()),
                    Span::styled(field.label.clone(), label_style),
                ]),
                Rect::new(area.x, y, label_width.min(area.width), 1),
            );
            let x = area.x + label_width;
            let width = area.width.saturating_sub(label_width);
            let input = Rect::new(x, y, width, 1);
            self.hits
                .push((Rect::new(area.x, y, area.width, 1), FormHit::Field(i)));
            match &field.kind {
                Kind::Text {
                    value,
                    cursor,
                    placeholder,
                    secret,
                } => {
                    let shown: String = if *secret {
                        "•".repeat(value.chars().count())
                    } else {
                        value.clone()
                    };
                    let style = Style::new().bg(theme::FIELD).fg(theme::TEXT);
                    // Scroll the text so the cursor stays visible.
                    let visible = width.saturating_sub(2) as usize;
                    let skip = cursor.saturating_sub(visible);
                    let text: String = shown.chars().skip(skip).collect();
                    let line = if value.is_empty() && !focused {
                        Line::from(Span::styled(
                            format!(" {placeholder}"),
                            style.fg(theme::MUTED),
                        ))
                    } else if value.is_empty() {
                        Line::from(vec![
                            Span::styled(" ", style),
                            Span::styled(
                                placeholder.clone(),
                                style.fg(theme::MUTED).add_modifier(Modifier::ITALIC),
                            ),
                        ])
                    } else {
                        Line::from(Span::styled(format!(" {text}"), style))
                    };
                    frame.render_widget(Paragraph::new(line).style(style), input);
                    if focused {
                        let cx = x + 1 + (cursor - skip) as u16;
                        if cx < x + width {
                            frame.set_cursor_position(Position::new(cx, y));
                        }
                    }
                }
                Kind::Select { options, index } => {
                    let label = options
                        .get(*index)
                        .map(|o| o.1.clone())
                        .unwrap_or_else(|| "(none)".into());
                    let style = if focused {
                        Style::new()
                            .bg(theme::FIELD)
                            .fg(theme::TEXT)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::new().bg(theme::FIELD).fg(theme::TEXT)
                    };
                    let count = format!(" {}/{} ", index + 1, options.len());
                    frame.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled(" ◂ ", theme::accent().bg(theme::FIELD)),
                            Span::styled(label, style),
                            Span::styled(count, theme::muted().bg(theme::FIELD)),
                            Span::styled(" ▸ ", theme::accent().bg(theme::FIELD)),
                        ]))
                        .style(Style::new().bg(theme::FIELD)),
                        input,
                    );
                    self.hits.push((Rect::new(x, y, 3, 1), FormHit::Prev(i)));
                    self.hits.push((
                        Rect::new(x + 3, y, width.saturating_sub(3), 1),
                        FormHit::Next(i),
                    ));
                }
                Kind::Check { on } => {
                    let (mark, style) = if *on {
                        ("[✓]", theme::ok().add_modifier(Modifier::BOLD))
                    } else {
                        ("[ ]", theme::muted())
                    };
                    frame.render_widget(
                        Line::from(vec![
                            Span::styled(mark, style),
                            Span::styled(if *on { " yes" } else { " no" }, theme::muted()),
                        ]),
                        input,
                    );
                }
            }
            y += 1;
            if let Some(hint) = &field.hint {
                if y < bottom {
                    frame.render_widget(
                        Paragraph::new(Span::styled(hint.clone(), theme::muted())),
                        Rect::new(x, y, width, 1),
                    );
                    y += 1;
                }
            }
        }
        if let Some(error) = &self.error {
            y += 1;
            let h = wrapped_lines(&format!("✗ {error}"), area.width);
            if y < bottom {
                frame.render_widget(
                    Paragraph::new(Span::styled(format!("✗ {error}"), theme::bad()))
                        .wrap(Wrap { trim: false }),
                    Rect::new(area.x, y, area.width, h.min(bottom - y)),
                );
            }
            y += h;
        }
        // Buttons, right-aligned on the last row.
        let y = (y + 1).min(bottom.saturating_sub(1));
        let submit = format!("  {}  ", self.submit);
        let cancel = "  Cancel  ".to_string();
        let total = (submit.chars().count() + cancel.chars().count() + 2) as u16;
        let mut x = area.x + area.width.saturating_sub(total);
        let n = self.buttons();
        let submit_style = match (self.focus == n, self.danger) {
            (true, true) => theme::button_danger(),
            (true, false) => theme::button_focus(),
            (false, true) => theme::button().fg(theme::BAD),
            (false, false) => theme::button(),
        };
        let w = submit.chars().count() as u16;
        frame.render_widget(Span::styled(submit, submit_style), Rect::new(x, y, w, 1));
        self.hits.push((Rect::new(x, y, w, 1), FormHit::Submit));
        x += w + 2;
        let w = cancel.chars().count() as u16;
        let cancel_style = if self.focus == n + 1 {
            theme::button_focus()
        } else {
            theme::button()
        };
        frame.render_widget(Span::styled(cancel, cancel_style), Rect::new(x, y, w, 1));
        self.hits.push((Rect::new(x, y, w, 1), FormHit::Cancel));
    }
}

fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(i, _)| i)
}

/// Rows `text` takes when wrapped at `width` (a rough word wrap, enough for sizing).
pub fn wrapped_lines(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.lines()
        .map(|line| {
            let mut rows = 1;
            let mut used = 0;
            for word in line.split(' ') {
                let len = word.chars().count();
                if used > 0 && used + 1 + len > width {
                    rows += 1;
                    used = len;
                } else {
                    used += if used > 0 { 1 + len } else { len };
                }
                while used > width {
                    rows += 1;
                    used -= width;
                }
            }
            rows
        })
        .sum::<u16>()
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn typing_editing_and_submitting() {
        let mut form = Form::new(
            "Add",
            "Add",
            vec![
                Field::text("name", "Name", "", "node1"),
                Field::select(
                    "mode",
                    "Mode",
                    vec![("a".into(), "A".into()), ("b".into(), "B".into())],
                ),
                Field::check("snat", "SNAT", false),
            ],
        );
        for c in "nodé2".chars() {
            form.key(key(KeyCode::Char(c)));
        }
        form.key(key(KeyCode::Left));
        form.key(key(KeyCode::Backspace));
        assert_eq!(form.text("name"), "nod2");
        form.paste("x\ny");
        assert_eq!(form.text("name"), "nodxy2");
        form.key(key(KeyCode::Tab));
        form.key(key(KeyCode::Left));
        assert_eq!(form.text("mode"), "b");
        form.key(key(KeyCode::Tab));
        form.key(key(KeyCode::Char(' ')));
        assert!(form.on("snat"));
        assert!(
            matches!(form.key(key(KeyCode::Enter)), Outcome::Submit),
            "Enter on a box submits"
        );
        assert!(form.on("snat"), "and leaves the box as it was");
        form.key(key(KeyCode::Tab));
        assert!(matches!(form.key(key(KeyCode::Enter)), Outcome::Submit));
        form.key(key(KeyCode::Tab));
        assert!(matches!(form.key(key(KeyCode::Enter)), Outcome::Cancel));
        assert!(matches!(form.key(key(KeyCode::Esc)), Outcome::Cancel));
    }

    #[test]
    fn wrapping_counts_rows() {
        assert_eq!(wrapped_lines("", 10), 1);
        assert_eq!(wrapped_lines("aaaa bbbb", 10), 1);
        assert_eq!(wrapped_lines("aaaa bbbb cccc", 10), 2);
        assert_eq!(wrapped_lines("a\nb", 10), 2);
        assert_eq!(wrapped_lines(&"x".repeat(25), 10), 3);
    }
}
