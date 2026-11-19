//! Colours and styles of the terminal UI: the violet-to-blue of the RIFT logo as the accent,
//! the web panel's status colours, and the terminal's own background everywhere but popups.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

pub const VIOLET: Color = Color::Rgb(0x8a, 0x2c, 0xff);
pub const SKY: Color = Color::Rgb(0x45, 0xb0, 0xff);
pub const ACCENT: Color = Color::Rgb(0x6d, 0x8f, 0xf0);
pub const OK: Color = Color::Rgb(0x4c, 0xc2, 0x7f);
pub const WARN: Color = Color::Rgb(0xe0, 0xa4, 0x47);
pub const BAD: Color = Color::Rgb(0xef, 0x6b, 0x6b);
pub const MUTED: Color = Color::Rgb(0x8b, 0x92, 0x9e);
pub const BORDER: Color = Color::Rgb(0x3d, 0x43, 0x50);
pub const SURFACE: Color = Color::Rgb(0x1a, 0x1d, 0x24);
pub const SELECTED: Color = Color::Rgb(0x2b, 0x33, 0x52);
pub const FIELD: Color = Color::Rgb(0x23, 0x27, 0x30);
pub const TEXT: Color = Color::Rgb(0xe6, 0xe8, 0xeb);

pub fn muted() -> Style {
    Style::new().fg(MUTED)
}
pub fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}
pub fn accent() -> Style {
    Style::new().fg(ACCENT)
}
pub fn ok() -> Style {
    Style::new().fg(OK)
}
pub fn warn() -> Style {
    Style::new().fg(WARN)
}
pub fn bad() -> Style {
    Style::new().fg(BAD)
}
pub fn border() -> Style {
    Style::new().fg(BORDER)
}
pub fn selected() -> Style {
    Style::new().bg(SELECTED).add_modifier(Modifier::BOLD)
}
pub fn popup() -> Style {
    Style::new().bg(SURFACE).fg(TEXT)
}
pub fn key() -> Style {
    Style::new()
        .fg(Color::Rgb(0x0d, 0x10, 0x20))
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}
pub fn button() -> Style {
    Style::new().fg(TEXT).bg(Color::Rgb(0x2f, 0x35, 0x44))
}
pub fn button_focus() -> Style {
    Style::new()
        .fg(Color::Rgb(0x0d, 0x10, 0x20))
        .bg(ACCENT)
        .add_modifier(Modifier::BOLD)
}
pub fn button_danger() -> Style {
    Style::new()
        .fg(Color::Rgb(0x20, 0x0d, 0x0d))
        .bg(BAD)
        .add_modifier(Modifier::BOLD)
}

/// `text` with its letters coloured along the logo's gradient, from violet to sky blue.
pub fn gradient(text: &str) -> Vec<Span<'static>> {
    let (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) = (VIOLET, SKY) else {
        return vec![Span::raw(text.to_string())];
    };
    let n = text.chars().count().max(2) - 1;
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * i as f32 / n as f32) as u8;
            Span::styled(
                c.to_string(),
                Style::new()
                    .fg(Color::Rgb(mix(r1, r2), mix(g1, g2), mix(b1, b2)))
                    .add_modifier(Modifier::BOLD),
            )
        })
        .collect()
}
