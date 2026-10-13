use ratatui::style::{Color, Modifier, Style};

#[path = "theme/palette.rs"]
#[allow(dead_code, unused_imports)]
mod palette;
use std::cell::RefCell;
thread_local! { static ACTIVE: RefCell<(String, palette::Theme)> = RefCell::new(("aurora".into(), palette::aurora())); }
pub fn set(id: &str) {
    let om = if id == "omarchy" {
        palette::find_omarchy().map(|(_, t, _)| t)
    } else {
        None
    };
    ACTIVE.with(|a| *a.borrow_mut() = (id.into(), palette::resolve(id, om.as_ref())));
}
pub fn refresh() {
    let id = ACTIVE.with(|a| a.borrow().0.clone());
    if id == "omarchy" {
        set(&id);
    }
}
pub fn load(path: &std::path::Path) {
    let id = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str::<toml::Value>(&s).ok())
        .and_then(|v| v.get("theme").and_then(|v| v.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "aurora".into());
    set(&id);
}
pub fn save(path: &std::path::Path, id: &str) -> std::io::Result<()> {
    let mut value = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str::<toml::Value>(&s).ok())
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    if let Some(table) = value.as_table_mut() {
        table.insert("theme".into(), toml::Value::String(id.into()));
    }
    std::fs::write(path, toml::to_string_pretty(&value).unwrap_or_default())
}
pub fn bg() -> Style {
    Style::default().bg(bg_color()).fg(fg())
}

pub fn title() -> Style {
    Style::default().fg(purple()).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::default().fg(pink()).add_modifier(Modifier::BOLD)
}

pub fn muted() -> Style {
    Style::default().fg(muted_color())
}

pub fn selected() -> Style {
    Style::default()
        .bg(current())
        .fg(purple())
        .add_modifier(Modifier::BOLD)
}

pub fn ok() -> Style {
    Style::default().fg(green())
}

pub fn warn() -> Style {
    Style::default().fg(orange())
}

pub fn err() -> Style {
    Style::default().fg(red())
}

pub fn ip() -> Style {
    Style::default().fg(cyan())
}

pub fn hostname() -> Style {
    Style::default().fg(yellow())
}

pub fn script() -> Style {
    Style::default().fg(purple())
}

pub fn port_state(state: &str) -> Style {
    let base = state.split('|').next().unwrap_or(state);
    match base {
        "open" => Style::default().fg(green()).add_modifier(Modifier::BOLD),
        "closed" => Style::default().fg(red()),
        "filtered" => Style::default().fg(orange()),
        "unfiltered" => Style::default().fg(cyan()),
        "down" => Style::default().fg(red()),
        "up" => Style::default().fg(green()).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(yellow()),
    }
}

pub fn bg_color() -> Color {
    ACTIVE.with(|a| a.borrow().1.bg)
}

pub fn current() -> Color {
    ACTIVE.with(|a| a.borrow().1.bg_raised)
}

pub fn fg() -> Color {
    ACTIVE.with(|a| a.borrow().1.fg)
}

pub fn comment() -> Color {
    ACTIVE.with(|a| a.borrow().1.border)
}

pub fn cyan() -> Color {
    ACTIVE.with(|a| a.borrow().1.cyan)
}

pub fn green() -> Color {
    ACTIVE.with(|a| a.borrow().1.green)
}

pub fn orange() -> Color {
    ACTIVE.with(|a| a.borrow().1.yellow)
}

pub fn pink() -> Color {
    ACTIVE.with(|a| a.borrow().1.accent)
}

pub fn purple() -> Color {
    ACTIVE.with(|a| a.borrow().1.accent)
}

pub fn red() -> Color {
    ACTIVE.with(|a| a.borrow().1.red)
}

pub fn yellow() -> Color {
    ACTIVE.with(|a| a.borrow().1.yellow)
}

pub fn muted_color() -> Color {
    ACTIVE.with(|a| a.borrow().1.muted)
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn theme_save_keeps_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"dracula\"\nhost = \"localhost\"\n").unwrap();
        load(&path);
        assert_eq!(bg_color(), Color::Rgb(0x28, 0x2a, 0x36));
        save(&path, "terminal").unwrap();
        load(&path);
        assert_eq!(bg_color(), Color::Reset);
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("localhost"));
        set("aurora");
        assert_eq!(bg_color(), Color::Rgb(0x17, 0x18, 0x20));
    }
}
