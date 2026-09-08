use ratatui::style::{Color, Modifier, Style};

/// Official Dracula palette: https://spec.draculatheme.com/
pub const BG: Color = Color::Rgb(0x28, 0x2a, 0x36);
pub const CURRENT: Color = Color::Rgb(0x44, 0x47, 0x5a);
pub const FG: Color = Color::Rgb(0xf8, 0xf8, 0xf2);
pub const COMMENT: Color = Color::Rgb(0x62, 0x72, 0xa4);
pub const CYAN: Color = Color::Rgb(0x8b, 0xe9, 0xfd);
pub const GREEN: Color = Color::Rgb(0x50, 0xfa, 0x7b);
pub const ORANGE: Color = Color::Rgb(0xff, 0xb8, 0x6c);
pub const PINK: Color = Color::Rgb(0xff, 0x79, 0xc6);
pub const PURPLE: Color = Color::Rgb(0xbd, 0x93, 0xf9);
pub const RED: Color = Color::Rgb(0xff, 0x55, 0x55);
pub const YELLOW: Color = Color::Rgb(0xf1, 0xfa, 0x8c);

pub fn bg() -> Style {
    Style::default().bg(BG).fg(FG)
}

pub fn title() -> Style {
    Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::default().fg(PINK).add_modifier(Modifier::BOLD)
}

pub fn muted() -> Style {
    Style::default().fg(COMMENT)
}

pub fn selected() -> Style {
    Style::default()
        .bg(CURRENT)
        .fg(FG)
        .add_modifier(Modifier::BOLD)
}

pub fn ok() -> Style {
    Style::default().fg(GREEN)
}

pub fn warn() -> Style {
    Style::default().fg(ORANGE)
}

pub fn err() -> Style {
    Style::default().fg(RED)
}

pub fn flag() -> Style {
    Style::default().fg(PINK)
}

pub fn ip() -> Style {
    Style::default().fg(CYAN)
}

pub fn hostname() -> Style {
    Style::default().fg(YELLOW)
}

pub fn script() -> Style {
    Style::default().fg(PURPLE)
}

pub fn port_state(state: &str) -> Style {
    let base = state.split('|').next().unwrap_or(state);
    match base {
        "open" => Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        "closed" => Style::default().fg(RED),
        "filtered" => Style::default().fg(ORANGE),
        "unfiltered" => Style::default().fg(CYAN),
        "down" => Style::default().fg(RED),
        "up" => Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(YELLOW),
    }
}
