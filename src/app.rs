use crate::export::{self, DiffLine, Format};
use crate::fields::{self, FormRow, ROWS, RowKind};
use crate::input::LineEdit;
use crate::nmap::args::{DnsMode, ScanSpec};
use crate::nmap::detect::{self, NmapInfo};
use crate::nmap::profiles::{builtin_profiles, by_name};
use crate::nmap::runner::{self, LiveScan, ScanEvent};
use crate::nmap::scripts::{self, CATEGORIES, NseScript};
use crate::nmap::xml::{self, Host, Port, ScanDocument};
use crate::persist::{self, HistoryEntry, HistoryFile, Paths};
use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Scan,
    Live,
    Results,
    History,
    Scripts,
    Compare,
}

impl Tab {
    pub fn all() -> [Tab; 6] {
        [
            Tab::Scan,
            Tab::Live,
            Tab::Results,
            Tab::History,
            Tab::Scripts,
            Tab::Compare,
        ]
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Scan => "1 Scan",
            Tab::Live => "2 Live",
            Tab::Results => "3 Results",
            Tab::History => "4 History",
            Tab::Scripts => "5 Scripts",
            Tab::Compare => "6 Compare",
        }
    }

    pub fn from_digit(c: char) -> Option<Tab> {
        Some(match c {
            '1' => Tab::Scan,
            '2' => Tab::Live,
            '3' => Tab::Results,
            '4' => Tab::History,
            '5' => Tab::Scripts,
            '6' => Tab::Compare,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanPane {
    Profiles,
    Targets,
    Options,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultPane {
    Ports,
    Scripts,
    Os,
    Raw,
}

impl ResultPane {
    fn next(self) -> Self {
        match self {
            ResultPane::Ports => ResultPane::Scripts,
            ResultPane::Scripts => ResultPane::Os,
            ResultPane::Os => ResultPane::Raw,
            ResultPane::Raw => ResultPane::Ports,
        }
    }
}

pub enum Modal {
    None,
    Help,
    ConfirmRun,
    ConfirmQuit,
    ConfirmDelete,
    Edit { title: String, id: String },
    Message { title: String, body: String },
    Import,
    Export { format: Format },
}

pub struct App {
    pub commands: crate::commands::Palette,
    pub tab: Tab,
    pub spec: ScanSpec,
    pub profile_idx: usize,
    pub profile_dirty: bool,
    pub nmap: NmapInfo,
    pub paths: Paths,
    pub history: HistoryFile,
    pub scripts: Vec<NseScript>,
    pub results: ScanDocument,
    pub live: Option<LiveScan>,
    pub scan_rx: Option<mpsc::Receiver<ScanEvent>>,
    pub should_quit: bool,
    pub status: String,
    pub modal: Modal,
    pub edit: LineEdit,
    pub scan_pane: ScanPane,
    pub option_idx: usize,
    pub host_idx: usize,
    pub port_idx: usize,
    pub result_pane: ResultPane,
    pub show_closed: bool,
    pub filter: String,
    pub filtering: bool,
    pub history_idx: usize,
    pub script_idx: usize,
    pub script_cat: usize,
    pub script_filter: String,
    pub compare_left: Option<usize>,
    pub compare_right: Option<usize>,
    pub compare_focus: u8,
    pub log_scroll: u16,
    pub log_follow: bool,
    pub help_scroll: u16,
    pub pending_start: Option<PendingStart>,
}

impl App {
    fn apply_aurora_theme(&mut self, id: &str) {
        if let Err(err) = crate::theme::save(&self.paths.config.join("config.toml"), id) {
            self.status = format!("Saving theme: {err}");
        }
        crate::theme::set(id);
    }

    pub fn new() -> anyhow::Result<Self> {
        Self::with_paths(Paths::resolve()?)
    }

    pub fn with_paths(paths: Paths) -> anyhow::Result<Self> {
        let nmap = detect::detect();
        let history = persist::load_history(&paths.history);
        crate::theme::load(&paths.config.join("config.toml"));
        let status = if nmap.present() {
            format!("{} · XML viewer + scanner ready", nmap.version_short())
        } else {
            "nmap not on PATH — XML viewing works; install nmap to scan".into()
        };
        let mut app = Self {
            commands: crate::commands::Palette::default(),
            tab: Tab::Scan,
            spec: ScanSpec::default(),
            profile_idx: 5, // Quick scan
            profile_dirty: false,
            nmap,
            paths,
            history,
            scripts: scripts::load_catalog(),
            results: ScanDocument::default(),
            live: None,
            scan_rx: None,
            should_quit: false,
            status,
            modal: Modal::None,
            edit: LineEdit::default(),
            scan_pane: ScanPane::Profiles,
            option_idx: fields::first_selectable(),
            host_idx: 0,
            port_idx: 0,
            result_pane: ResultPane::Ports,
            show_closed: false,
            filter: String::new(),
            filtering: false,
            history_idx: 0,
            script_idx: 0,
            script_cat: 0,
            script_filter: String::new(),
            compare_left: None,
            compare_right: None,
            compare_focus: 0,
            log_scroll: 0,
            log_follow: true,
            help_scroll: 0,
            pending_start: None,
        };
        app.apply_profile(app.profile_idx);
        Ok(app)
    }

    pub fn apply_cli(
        &mut self,
        target: Option<String>,
        profile: Option<String>,
        open: Option<std::path::PathBuf>,
        nmap_args: Vec<String>,
    ) -> anyhow::Result<()> {
        if let Some(name) = profile {
            if let Some(p) = by_name(&name) {
                let idx = builtin_profiles()
                    .iter()
                    .position(|x| x.name == p.name)
                    .unwrap();
                self.apply_profile(idx);
            } else {
                self.status = format!("unknown profile '{name}'");
            }
        }
        if let Some(t) = target {
            self.spec.targets = t;
        }
        if !nmap_args.is_empty() {
            let mut args = nmap_args;
            if args
                .first()
                .is_some_and(|s| s != "nmap" && !s.ends_with("/nmap"))
            {
                args.insert(0, "nmap".into());
            }
            self.spec = ScanSpec::from_argv(&args);
            self.profile_dirty = true;
        }
        if let Some(path) = open {
            self.import_xml(&path)?;
        }
        Ok(())
    }

    fn apply_profile(&mut self, idx: usize) {
        let targets = self.spec.targets.clone();
        self.spec = builtin_profiles()[idx].spec();
        self.spec.targets = targets;
        self.profile_idx = idx;
        self.profile_dirty = false;
    }

    pub fn profile_label(&self) -> String {
        let name = builtin_profiles()[self.profile_idx].name;
        if self.profile_dirty {
            format!("{name} *")
        } else {
            name.into()
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.filtering {
            self.handle_filter_key(key);
            return;
        }
        if !matches!(self.modal, Modal::None) {
            self.handle_modal_key(key);
            return;
        }

        if self.commands.open
            || (key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            if let Some(action) = self.commands.handle(key, ACTIONS) {
                if action.modifiers == KeyModifiers::ALT {
                    let id = match action.key {
                        KeyCode::Char('o') => "omarchy",
                        KeyCode::Char('t') => "terminal",
                        _ => "aurora",
                    };
                    self.apply_aurora_theme(id);
                } else {
                    self.handle_key(action.event());
                }
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => {
                if self.live.as_ref().is_some_and(|l| l.running()) {
                    self.modal = Modal::ConfirmQuit;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(live) = self.live.as_mut() {
                    if live.running() {
                        live.request_cancel();
                        self.status =
                            "SIGINT sent to nmap (resume from History if incomplete)".into();
                        return;
                    }
                }
                self.should_quit = true;
            }
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Char(c @ '1'..='6') => {
                if let Some(t) = Tab::from_digit(c) {
                    self.tab = t;
                }
            }
            KeyCode::Tab => self.cycle_pane(1),
            KeyCode::BackTab => self.cycle_pane(-1),
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.prompt_run();
            }
            KeyCode::Char('y') if self.tab == Tab::Scan => {
                self.yank(&self.spec.preview_command());
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                self.edit = LineEdit::new(match self.tab {
                    Tab::Scripts => self.script_filter.clone(),
                    _ => self.filter.clone(),
                });
            }
            _ => match self.tab {
                Tab::Scan => self.handle_scan_key(key),
                Tab::Live => self.handle_live_key(key),
                Tab::Results => self.handle_results_key(key),
                Tab::History => self.handle_history_key(key),
                Tab::Scripts => self.handle_scripts_key(key),
                Tab::Compare => self.handle_compare_key(key),
            },
        }
    }

    fn cycle_pane(&mut self, dir: isize) {
        if self.tab == Tab::Scan {
            self.scan_pane = match (self.scan_pane, dir) {
                (ScanPane::Profiles, 1) | (ScanPane::Options, -1) => ScanPane::Targets,
                (ScanPane::Targets, 1) | (ScanPane::Profiles, -1) => ScanPane::Options,
                (ScanPane::Options, 1) | (ScanPane::Targets, -1) => ScanPane::Profiles,
                _ => self.scan_pane,
            };
        } else if self.tab == Tab::Results {
            self.result_pane = self.result_pane.next();
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filtering = false;
            }
            KeyCode::Enter => {
                let v = self.edit.value.clone();
                if self.tab == Tab::Scripts {
                    self.script_filter = v;
                    self.script_idx = 0;
                } else {
                    self.filter = v;
                    self.host_idx = 0;
                }
                self.filtering = false;
            }
            _ => {
                self.edit.handle(key);
            }
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match &self.modal {
            Modal::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => self.modal = Modal::None,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1);
                }
                _ => {}
            },
            Modal::Message { .. } => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                    self.modal = Modal::None;
                }
            }
            Modal::ConfirmRun => match key.code {
                KeyCode::Esc | KeyCode::Char('n') => self.modal = Modal::None,
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.modal = Modal::None;
                    self.start_scan(false);
                }
                _ => {}
            },
            Modal::ConfirmQuit => match key.code {
                KeyCode::Esc | KeyCode::Char('n') => self.modal = Modal::None,
                KeyCode::Enter | KeyCode::Char('y') => {
                    if let Some(live) = self.live.as_mut() {
                        live.request_cancel();
                    }
                    self.should_quit = true;
                }
                _ => {}
            },
            Modal::ConfirmDelete => match key.code {
                KeyCode::Esc | KeyCode::Char('n') => self.modal = Modal::None,
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.modal = Modal::None;
                    self.delete_history();
                }
                _ => {}
            },
            Modal::Edit { id, .. } => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Enter => {
                    let id = id.clone();
                    let v = self.edit.value.clone();
                    self.spec.set_text(&id, v);
                    self.profile_dirty = true;
                    self.modal = Modal::None;
                }
                _ => {
                    self.edit.handle(key);
                }
            },
            Modal::Import => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Enter => {
                    let path = std::path::PathBuf::from(self.edit.value.trim());
                    self.modal = Modal::None;
                    match self.import_xml(&path) {
                        Ok(()) => self.status = format!("imported {}", path.display()),
                        Err(e) => self.message("Import failed", e.to_string()),
                    }
                }
                _ => {
                    self.edit.handle(key);
                }
            },
            Modal::Export { format } => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Enter => {
                    let fmt = *format;
                    let path = std::path::PathBuf::from(self.edit.value.trim());
                    self.modal = Modal::None;
                    match fmt
                        .render(&self.results)
                        .and_then(|s| export::write(&path, &s))
                    {
                        Ok(()) => self.status = format!("wrote {}", path.display()),
                        Err(e) => self.message("Export failed", e.to_string()),
                    }
                }
                _ => {
                    self.edit.handle(key);
                }
            },
            Modal::None => {}
        }
    }

    fn handle_scan_key(&mut self, key: KeyEvent) {
        match self.scan_pane {
            ScanPane::Profiles => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.profile_idx = (self.profile_idx + 1) % builtin_profiles().len();
                    self.apply_profile(self.profile_idx);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.profile_idx = if self.profile_idx == 0 {
                        builtin_profiles().len() - 1
                    } else {
                        self.profile_idx - 1
                    };
                    self.apply_profile(self.profile_idx);
                }
                KeyCode::Enter => self.apply_profile(self.profile_idx),
                _ => {}
            },
            ScanPane::Targets => match key.code {
                KeyCode::Enter => {
                    self.edit = LineEdit::new(self.spec.targets.clone());
                    self.modal = Modal::Edit {
                        title: "Targets (hosts, CIDR, ranges)".into(),
                        id: "targets".into(),
                    };
                }
                _ => {}
            },
            ScanPane::Options => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.option_idx = fields::next_selectable(self.option_idx, 1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.option_idx = fields::next_selectable(self.option_idx, -1);
                }
                KeyCode::Char(' ') | KeyCode::Enter => self.activate_option(),
                _ => {}
            },
        }
    }

    fn activate_option(&mut self) {
        let row = &ROWS[self.option_idx];
        match row.kind {
            RowKind::Header => {}
            RowKind::Bool => {
                self.spec.toggle_bool(row.id);
                self.profile_dirty = true;
            }
            RowKind::TcpScan => {
                self.spec.cycle_tcp_scan();
                self.profile_dirty = true;
            }
            RowKind::Dns => {
                self.spec.cycle_dns();
                self.profile_dirty = true;
            }
            RowKind::Text => {
                self.edit = LineEdit::new(self.spec.get_text(row.id));
                self.modal = Modal::Edit {
                    title: format!("{}  {}", row.label, row.hint),
                    id: row.id.into(),
                };
            }
        }
    }

    fn handle_live_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.log_follow = false;
                self.log_scroll = self.log_scroll.saturating_add(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll = self.log_scroll.saturating_sub(1);
                if self.log_scroll == 0 {
                    self.log_follow = true;
                }
            }
            KeyCode::Char('G') => {
                self.log_scroll = 0;
                self.log_follow = true;
            }
            KeyCode::Enter => {
                self.tab = Tab::Results;
            }
            _ => {}
        }
    }

    fn handle_results_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('h') | KeyCode::Left => {
                if self.host_idx > 0 {
                    self.host_idx -= 1;
                    self.port_idx = 0;
                }
            }
            KeyCode::Char('l') | KeyCode::Right => {
                let n = self.filtered_hosts().len();
                if self.host_idx + 1 < n {
                    self.host_idx += 1;
                    self.port_idx = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.current_ports().len();
                if n > 0 {
                    self.port_idx = (self.port_idx + 1).min(n - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.port_idx = self.port_idx.saturating_sub(1);
            }
            KeyCode::Char('o') => self.show_closed = !self.show_closed,
            KeyCode::Char('e') => self.prompt_export(Format::Json),
            KeyCode::Char('m') => self.prompt_export(Format::Markdown),
            KeyCode::Char('c') => self.prompt_export(Format::Csv),
            KeyCode::Char('[') => {
                self.result_pane = match self.result_pane {
                    ResultPane::Ports => ResultPane::Raw,
                    ResultPane::Scripts => ResultPane::Ports,
                    ResultPane::Os => ResultPane::Scripts,
                    ResultPane::Raw => ResultPane::Os,
                };
            }
            KeyCode::Char(']') => self.result_pane = self.result_pane.next(),
            _ => {}
        }
    }

    fn handle_history_key(&mut self, key: KeyEvent) {
        let n = self.history.entries.len();
        if n == 0 {
            if key.code == KeyCode::Char('i') {
                self.prompt_import();
            }
            return;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.history_idx = (self.history_idx + 1) % n;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.history_idx = if self.history_idx == 0 {
                    n - 1
                } else {
                    self.history_idx - 1
                };
            }
            KeyCode::Enter => {
                if let Some(e) = self.history.entries.get(self.history_idx).cloned() {
                    match persist::load_scan_xml(&e.dir) {
                        Ok(doc) => {
                            self.results = doc;
                            self.tab = Tab::Results;
                            self.host_idx = 0;
                            self.status = format!("opened {}", e.command);
                        }
                        Err(err) => self.message("Open failed", err.to_string()),
                    }
                }
            }
            KeyCode::Char('R') => self.rerun_history(),
            KeyCode::Char('r') => self.resume_history(),
            KeyCode::Char('d') => self.modal = Modal::ConfirmDelete,
            KeyCode::Char('i') => self.prompt_import(),
            _ => {}
        }
    }

    fn handle_scripts_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.filtered_scripts().len();
                if n > 0 {
                    self.script_idx = (self.script_idx + 1) % n;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let n = self.filtered_scripts().len();
                if n > 0 {
                    self.script_idx = if self.script_idx == 0 {
                        n - 1
                    } else {
                        self.script_idx - 1
                    };
                }
            }
            KeyCode::Char(' ') => {
                let name = self
                    .filtered_scripts()
                    .get(self.script_idx)
                    .map(|s| s.name.clone());
                if let Some(name) = name {
                    self.toggle_script(&name);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.script_cat = if self.script_cat == 0 {
                    CATEGORIES.len()
                } else {
                    self.script_cat - 1
                };
                self.script_idx = 0;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.script_cat = (self.script_cat + 1) % (CATEGORIES.len() + 1);
                self.script_idx = 0;
            }
            _ => {}
        }
    }

    fn handle_compare_key(&mut self, key: KeyEvent) {
        let n = self.history.entries.len();
        match key.code {
            KeyCode::Tab => self.compare_focus = (self.compare_focus + 1) % 2,
            KeyCode::Down | KeyCode::Char('j') => {
                if n == 0 {
                    return;
                }
                let slot = if self.compare_focus == 0 {
                    &mut self.compare_left
                } else {
                    &mut self.compare_right
                };
                let cur = slot.unwrap_or(0);
                *slot = Some((cur + 1) % n);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if n == 0 {
                    return;
                }
                let slot = if self.compare_focus == 0 {
                    &mut self.compare_left
                } else {
                    &mut self.compare_right
                };
                let cur = slot.unwrap_or(0);
                *slot = Some(if cur == 0 { n - 1 } else { cur - 1 });
            }
            KeyCode::Enter => {
                if self.compare_focus == 0 {
                    self.compare_left = Some(self.history_idx.min(n.saturating_sub(1)));
                } else {
                    self.compare_right = Some(self.history_idx.min(n.saturating_sub(1)));
                }
            }
            _ => {}
        }
    }

    fn toggle_script(&mut self, name: &str) {
        let mut parts: Vec<String> = self
            .spec
            .scripts
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(i) = parts.iter().position(|p| p == name) {
            parts.remove(i);
        } else {
            parts.push(name.to_string());
        }
        self.spec.scripts = if parts.is_empty() {
            None
        } else {
            Some(parts.join(","))
        };
        self.profile_dirty = true;
        self.status = format!(
            "--script {}",
            self.spec.scripts.as_deref().unwrap_or("(none)")
        );
    }

    pub fn filtered_scripts(&self) -> Vec<&NseScript> {
        let q = self.script_filter.to_ascii_lowercase();
        self.scripts
            .iter()
            .filter(|s| {
                if self.script_cat > 0 {
                    let cat = CATEGORIES[self.script_cat - 1];
                    if !s.categories.iter().any(|c| c.eq_ignore_ascii_case(cat)) {
                        return false;
                    }
                }
                q.is_empty()
                    || s.name.to_ascii_lowercase().contains(&q)
                    || s.categories
                        .iter()
                        .any(|c| c.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    pub fn filtered_hosts(&self) -> Vec<&Host> {
        let q = self.filter.to_ascii_lowercase();
        self.results
            .hosts
            .iter()
            .filter(|h| {
                if q.is_empty() {
                    return true;
                }
                h.primary_ip().to_ascii_lowercase().contains(&q)
                    || h.hostname().to_ascii_lowercase().contains(&q)
                    || h.os_guess().to_ascii_lowercase().contains(&q)
                    || h.ports.iter().any(|p| {
                        p.portid.contains(&q)
                            || p.service.to_ascii_lowercase().contains(&q)
                            || p.product.to_ascii_lowercase().contains(&q)
                            || p.scripts.iter().any(|s| s.id.contains(&q))
                    })
            })
            .collect()
    }

    pub fn current_host(&self) -> Option<&Host> {
        self.filtered_hosts().get(self.host_idx).copied()
    }

    pub fn current_ports(&self) -> Vec<&Port> {
        let Some(h) = self.current_host() else {
            return Vec::new();
        };
        h.ports
            .iter()
            .filter(|p| self.show_closed || p.state == "open" || p.state.contains("open"))
            .collect()
    }

    pub fn option_value(&self, row: &FormRow) -> String {
        match row.kind {
            RowKind::Header => String::new(),
            RowKind::Bool => {
                if self.spec.get_bool(row.id) {
                    "[x]".into()
                } else {
                    "[ ]".into()
                }
            }
            RowKind::TcpScan => self.spec.tcp_scan.label().into(),
            RowKind::Dns => match self.spec.dns {
                DnsMode::Default => "default".into(),
                DnsMode::Never => "never (-n)".into(),
                DnsMode::Always => "always (-R)".into(),
            },
            RowKind::Text => {
                let v = self.spec.get_text(row.id);
                if v.is_empty() { "—".into() } else { v }
            }
        }
    }

    fn prompt_run(&mut self) {
        if self.live.as_ref().is_some_and(|l| l.running()) {
            self.message("Scan running", "Cancel with Ctrl-C first.");
            return;
        }
        if !self.nmap.present() {
            self.message(
                "nmap missing",
                "Install nmap and ensure it is on PATH.\nOn Debian/Ubuntu: sudo apt install nmap\nYou can still open XML from History (i).",
            );
            return;
        }
        if !self.spec.has_targets() {
            self.message("No targets", "Enter hosts, CIDR, -iL, or -iR first.");
            return;
        }
        self.modal = Modal::ConfirmRun;
    }

    fn start_scan(&mut self, resume: bool) {
        let escalate = self.spec.needs_root() && !self.nmap.euid_root;
        let spec = self.spec.clone();
        let _ = resume;
        self.pending_start = Some(PendingStart { spec, escalate });
    }

    fn message(&mut self, title: impl Into<String>, body: impl Into<String>) {
        self.modal = Modal::Message {
            title: title.into(),
            body: body.into(),
        };
    }

    fn yank(&mut self, s: &str) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(s.to_string())) {
            Ok(()) => self.status = "copied command to clipboard".into(),
            Err(e) => self.status = format!("clipboard: {e}"),
        }
    }

    fn prompt_import(&mut self) {
        self.edit = LineEdit::new("");
        self.modal = Modal::Import;
    }

    fn prompt_export(&mut self, format: Format) {
        let name = match format {
            Format::Json => "scan.json",
            Format::Markdown => "scan.md",
            Format::Csv => "scan.csv",
        };
        self.edit = LineEdit::new(name);
        self.modal = Modal::Export { format };
    }

    fn import_xml(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        let xml = std::fs::read_to_string(path)?;
        let doc = xml::parse_document(&xml)?;
        self.results = doc;
        self.tab = Tab::Results;
        self.host_idx = 0;
        Ok(())
    }

    fn delete_history(&mut self) {
        if self.history_idx >= self.history.entries.len() {
            return;
        }
        let e = self.history.entries.remove(self.history_idx);
        let _ = std::fs::remove_dir_all(&e.dir);
        if self.history_idx >= self.history.entries.len() {
            self.history_idx = self.history.entries.len().saturating_sub(1);
        }
        let _ = persist::save_history(&self.paths.history, &self.history);
        self.status = format!("deleted {}", e.id);
    }

    fn rerun_history(&mut self) {
        if let Some(e) = self.history.entries.get(self.history_idx) {
            self.spec = ScanSpec::from_argv(&{
                let mut a = vec!["nmap".into()];
                a.extend(e.argv.iter().cloned());
                a
            });
            self.spec.targets = e.targets.clone();
            self.profile_dirty = true;
            self.tab = Tab::Scan;
            self.prompt_run();
        }
    }

    fn resume_history(&mut self) {
        if let Some(e) = self.history.entries.get(self.history_idx) {
            if e.status == "complete" {
                self.status = "scan already complete".into();
                return;
            }
            let xml = e.dir.join("scan.xml");
            self.spec = ScanSpec::default();
            self.spec.extra = format!("--resume {}", xml.display());
            self.spec.targets.clear();
            self.profile_dirty = true;
            self.prompt_run();
        }
    }

    pub fn diff_lines(&self) -> Vec<DiffLine> {
        let load = |i: Option<usize>| {
            i.and_then(|i| self.history.entries.get(i))
                .and_then(|e| persist::load_scan_xml(&e.dir).ok())
        };
        match (load(self.compare_left), load(self.compare_right)) {
            (Some(a), Some(b)) => export::compare(&a, &b),
            _ => vec![DiffLine {
                kind: export::DiffKind::Same,
                text: "pick two history scans (Tab switches side, j/k selects)".into(),
            }],
        }
    }

    pub async fn on_tick(&mut self) {
        crate::theme::refresh();
        self.drain_scan_events();
        if let Some(p) = self.pending_start.take() {
            self.launch(p).await;
        }
        let mut exit_code = None;
        let mut xml_path = None;
        let mut force_kill = false;
        if let Some(live) = self.live.as_mut() {
            if live.cancel_requested
                && live
                    .cancel_at
                    .is_some_and(|t| t.elapsed() > Duration::from_secs(3))
            {
                force_kill = true;
            }
            if let Some(child) = live.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    exit_code = Some(status.code());
                }
            }
            xml_path = Some(live.xml_path.clone());
        }
        if force_kill {
            if let Some(live) = self.live.as_mut() {
                live.force_kill();
            }
        }
        if let Some(code) = exit_code {
            if let Some(live) = self.live.as_mut() {
                live.child = None;
            }
            self.finish_scan(code);
        } else if let Some(path) = xml_path {
            if path.exists() {
                if let Ok(xml) = std::fs::read_to_string(path) {
                    self.results.merge_partial(xml::parse_partial(&xml));
                }
            }
        }
    }

    fn drain_scan_events(&mut self) {
        let mut lines = Vec::new();
        if let Some(rx) = self.scan_rx.as_mut() {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    ScanEvent::Stdout(l) | ScanEvent::Stderr(l) => lines.push(l),
                    ScanEvent::Exited { code } => self.status = format!("nmap exited {code:?}"),
                }
            }
        }
        if let Some(live) = self.live.as_mut() {
            for l in lines {
                if runner::looks_like_stats(&l) {
                    live.stats_line = l.clone();
                }
                live.log.push(l);
                if live.log.len() > 5000 {
                    live.log.drain(0..live.log.len() - 4000);
                }
            }
        }
    }

    async fn launch(&mut self, pending: PendingStart) {
        match runner::start(
            &pending.spec,
            &self.nmap,
            &self.paths.scans,
            pending.escalate,
        )
        .await
        {
            Ok((scan, rx)) => {
                self.results = ScanDocument::default();
                let entry = HistoryEntry {
                    id: scan.id.clone(),
                    started: scan.started,
                    finished: None,
                    argv: scan.argv.clone(),
                    targets: pending.spec.targets.clone(),
                    profile: Some(self.profile_label()),
                    dir: scan.dir.clone(),
                    status: "running".into(),
                    hosts_up: 0,
                    hosts_total: 0,
                    command: scan.display_cmd.clone(),
                };
                persist::upsert(&mut self.history, entry.clone());
                let _ = persist::write_meta(&scan.dir, &entry);
                let _ = persist::save_history(&self.paths.history, &self.history);
                self.status = if scan.used_sudo {
                    "started with sudo -n".into()
                } else {
                    "scan started".into()
                };
                self.live = Some(scan);
                self.scan_rx = Some(rx);
                self.tab = Tab::Live;
                self.log_follow = true;
                self.log_scroll = 0;
            }
            Err(e) => self.message("Failed to start nmap", e.to_string()),
        }
    }

    fn finish_scan(&mut self, code: Option<i32>) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        let id = live.id.clone();
        let dir = live.dir.clone();
        let xml_path = live.xml_path.clone();
        let cancel = live.cancel_requested;
        if xml_path.exists() {
            if let Ok(xml) = std::fs::read_to_string(&xml_path) {
                self.results = xml::parse_partial(&xml);
            }
        }
        let status = if cancel {
            "interrupted"
        } else if code == Some(0) {
            "complete"
        } else {
            "failed"
        };
        if let Some(e) = self.history.entries.iter_mut().find(|e| e.id == id) {
            e.finished = Some(Utc::now());
            e.status = status.into();
            e.hosts_up = self.results.hosts_up() as u32;
            e.hosts_total = self.results.hosts.len() as u32;
            let _ = persist::write_meta(&dir, e);
        }
        let _ = persist::save_history(&self.paths.history, &self.history);
        self.status = format!("scan {status} (exit {code:?})");
        if !self.results.hosts.is_empty() {
            self.tab = Tab::Results;
        }
        if let Some(live) = self.live.as_mut() {
            live.child = None;
        }
    }
}

pub struct PendingStart {
    pub spec: ScanSpec,
    pub escalate: bool,
}

pub const ACTIONS: &[crate::commands::Action] = &[
    crate::commands::Action::key("Scan builder", '1'),
    crate::commands::Action::key("Live scan", '2'),
    crate::commands::Action::key("Results", '3'),
    crate::commands::Action::key("History", '4'),
    crate::commands::Action::key("Scripts", '5'),
    crate::commands::Action::key("Compare", '6'),
    crate::commands::Action::ctrl("Review and run scan", 'g'),
    crate::commands::Action::key("Copy command", 'y'),
    crate::commands::Action::key("Filter", '/'),
    crate::commands::Action::key("Help", '?'),
    crate::commands::Action::theme("Aurora theme", 'a'),
    crate::commands::Action::theme("Follow Omarchy theme", 'o'),
    crate::commands::Action::theme("Terminal theme", 't'),
];
