const NAV_SCREENS: &[crate::navigation::Screen] = &[
    crate::navigation::Screen {
        name: "Scan",
        key: '1',
    },
    crate::navigation::Screen {
        name: "Live",
        key: '2',
    },
    crate::navigation::Screen {
        name: "Results",
        key: '3',
    },
    crate::navigation::Screen {
        name: "History",
        key: '4',
    },
    crate::navigation::Screen {
        name: "Scripts",
        key: '5',
    },
    crate::navigation::Screen {
        name: "Compare",
        key: '6',
    },
];
impl App {
    pub fn navigation_skin(&self) -> crate::navigation::Skin {
        crate::navigation::Skin {
            base: crate::theme::bg(),
            muted: crate::theme::muted(),
            accent: crate::theme::title(),
            selected: crate::theme::selected(),
            border: ratatui::style::Style::default().fg(crate::theme::comment()),
        }
    }
    pub fn navigation_screen(&self) -> usize {
        Tab::all().iter().position(|t| *t == self.tab).unwrap_or(0)
    }
    pub fn pane_names(&self) -> &'static [&'static str] {
        match self.tab {
            Tab::Scan => &["Profiles", "Targets", "Options"],
            Tab::Live => &["Output", "Hosts"],
            Tab::Results => &["Hosts", "Details"],
            Tab::History => &["History"],
            Tab::Scripts => &["Categories", "Scripts"],
            Tab::Compare => &["Older scan", "Newer scan", "Diff"],
        }
    }
    pub fn focused_pane(&self) -> usize {
        match self.tab {
            Tab::Scan => match self.scan_pane {
                ScanPane::Profiles => 0,
                ScanPane::Targets => 1,
                ScanPane::Options => 2,
            },
            Tab::Compare => self.compare_focus as usize,
            _ => self.navigation.focus[self.navigation_screen()],
        }
    }
    pub fn navigation_editing(&self) -> bool {
        false
    }
    pub fn navigation_entries(&self) -> Vec<crate::navigation::Entry> {
        crate::navigation::entries(NAV_SCREENS, self.pane_names())
    }
    pub fn navigation_bar(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.navigation.bar(
            frame,
            area,
            NAV_SCREENS,
            self.navigation_screen(),
            self.pane_names(),
            self.focused_pane(),
            self.navigation_editing(),
            self.navigation_skin(),
        );
    }
    pub fn draw_navigation(&self, frame: &mut ratatui::Frame) {
        self.navigation
            .draw(frame, &self.navigation_entries(), self.navigation_skin());
    }
    pub fn focus_pane(&mut self, p: usize) {
        let p = p.min(self.pane_names().len().saturating_sub(1));
        let screen = self.navigation_screen();
        self.navigation.focus[screen] = p;
        match self.tab {
            Tab::Scan => {
                self.scan_pane = match p {
                    0 => ScanPane::Profiles,
                    1 => ScanPane::Targets,
                    _ => ScanPane::Options,
                }
            }
            Tab::Compare => self.compare_focus = p as u8,
            _ => {}
        }
    }
    pub fn select_screen(&mut self, screen: usize) {
        if screen >= NAV_SCREENS.len() {
            return;
        }
        let old = self.navigation_screen();
        if old == screen {
            return;
        }
        self.navigation.focus[old] = self.focused_pane();
        self.tab = Tab::all()[screen];
        self.focus_pane(self.navigation.focus[screen]);
    }
    fn navigation_key(&mut self, key: KeyEvent) -> bool {
        if self.commands.open {
            return false;
        }
        if self.navigation.open {
            let entries = self.navigation_entries();
            if let Some(intent) = self.navigation.key(key, &entries) {
                self.dispatch_intent(intent);
            }
            return true;
        }
        match key.code {
            KeyCode::F(2) => {
                self.navigation.toggle();
                true
            }
            KeyCode::F(6) => {
                let direction = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    -1
                } else {
                    1
                };
                self.focus_pane(crate::navigation::step(
                    self.focused_pane(),
                    self.pane_names().len(),
                    direction,
                ));
                true
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if !self.navigation_editing() {
                    let d = if key.code == KeyCode::Tab {
                        -1i32 + 2
                    } else {
                        -1
                    };
                    self.select_screen(crate::navigation::step(
                        self.navigation_screen(),
                        NAV_SCREENS.len(),
                        d,
                    ));
                }
                true
            }
            KeyCode::Char(c)
                if !self.navigation_editing()
                    && key.modifiers.is_empty()
                    && NAV_SCREENS.iter().any(|s| s.key == c) =>
            {
                let i = NAV_SCREENS.iter().position(|s| s.key == c).unwrap();
                self.select_screen(i);
                true
            }
            KeyCode::Esc => {
                let p = if self.navigation_editing()
                    && self.focused_pane() == 0
                    && self.pane_names().len() > 1
                {
                    1
                } else {
                    self.focused_pane().saturating_sub(1)
                };
                self.focus_pane(p);
                true
            }
            KeyCode::Down | KeyCode::Up | KeyCode::Char('j' | 'k')
                if !self.navigation_editing()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let d = if matches!(key.code, KeyCode::Down | KeyCode::Char('j')) {
                    1
                } else {
                    -1
                };
                self.navigation_scroll(self.focused_pane(), d);
                true
            }
            KeyCode::PageDown | KeyCode::PageUp
                if !self.navigation_editing()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let d = if key.code == KeyCode::PageDown { 8 } else { -8 };
                self.navigation_scroll(self.focused_pane(), d);
                true
            }
            KeyCode::F(1) => {
                self.modal = Modal::Help;
                true
            }
            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.navigation_cancel();
                true
            }
            _ => false,
        }
    }
    fn navigation_cancel(&mut self) {
        if let Some(live) = self.live.as_mut() {
            if live.running() {
                live.request_cancel();
                self.status = "Cancelling scan…".into();
                return;
            }
        }
        self.status = "No scan is running".into();
    }
    pub fn dispatch_intent(&mut self, intent: crate::navigation::Intent) {
        use crate::navigation::Intent;
        match intent {
            Intent::Screen(screen) => {
                self.navigation.open = false;
                self.select_screen(screen)
            }
            Intent::Pane(p) => {
                self.navigation.open = false;
                self.focus_pane(p)
            }
            Intent::Menu => self.navigation.toggle(),
            Intent::Details(p) => self.focus_pane(p),
            Intent::ScrollDetails(p, d) => {
                self.focus_pane(p);
                self.navigation_details_scroll(p, d)
            }
            Intent::Selector(i) => {
                self.navigation.open = false;
                self.navigation_selector(i)
            }
            Intent::Theme(id) => self.apply_aurora_theme(id),
            Intent::Command(id) => self.navigation_command(id),
            Intent::Row(p, i) => {
                self.focus_pane(p);
                self.navigation_row(p, i, false)
            }
            Intent::Activate(p, i) => {
                self.focus_pane(p);
                self.navigation_row(p, i, true)
            }
            Intent::Scroll(p, d) => {
                self.focus_pane(p);
                self.navigation_scroll(p, d)
            }
        }
    }
    pub fn command_actions(&self) -> Vec<crate::commands::Action> {
        let mut actions = NAV_SCREENS
            .iter()
            .enumerate()
            .map(|(i, s)| crate::commands::Action::screen(s.name, i, s.key))
            .collect::<Vec<_>>();
        actions.extend(self.pane_names().iter().enumerate().map(|(i, p)| {
            crate::commands::Action::function(p, 6, crate::navigation::Intent::Pane(i))
        }));
        actions.push(crate::commands::Action::function(
            "Navigate",
            2,
            crate::navigation::Intent::Menu,
        ));
        actions.extend(
            ACTIONS
                .iter()
                .filter(|a| !matches!(a.key, KeyCode::Char('0'..='9')))
                .cloned(),
        );
        for action in &mut actions {
            let reason = match action.label {
                "Filter" if !matches!(self.tab, Tab::Results | Tab::Scripts) => {
                    Some("Filtering is available in Results and Scripts")
                }
                "Review and run scan" if self.live.as_ref().is_some_and(|l| l.running()) => {
                    Some("Cancel or finish the current scan first")
                }
                _ => None,
            };
            if let Some(reason) = reason {
                action.disabled = Some(reason.into());
            }
        }
        actions
    }
}

impl App {
    fn navigation_command(&mut self, id: &str) {
        match id {
            "Confirm" => match self.modal {
                Modal::ConfirmRun => {
                    self.modal = Modal::None;
                    self.start_scan(false)
                }
                Modal::ConfirmQuit => {
                    if let Some(live) = self.live.as_mut() {
                        live.request_cancel();
                    }
                    self.should_quit = true;
                }
                Modal::ConfirmDelete => {
                    self.modal = Modal::None;
                    self.delete_history();
                }
                _ => {}
            },
            "Cancel" => self.modal = Modal::None,
            "Result ports" => self.navigation_selector(0),
            "Result scripts" => self.navigation_selector(1),
            "Result OS" => self.navigation_selector(2),
            "Result XML" => self.navigation_selector(3),
            "Review and run scan" => self.prompt_run(),
            "Copy command" => {
                let text = self.spec.preview_command();
                self.yank(&text)
            }
            "Filter" => {
                self.filtering = true;
                self.edit = LineEdit::new(if self.tab == Tab::Scripts {
                    self.script_filter.clone()
                } else {
                    self.filter.clone()
                });
            }
            "Help" => self.modal = Modal::Help,
            "Import XML" => self.prompt_import(),
            _ => {}
        }
    }
    fn navigation_row(&mut self, pane: usize, index: usize, activate: bool) {
        match self.tab {
            Tab::Scan => match pane {
                0 => {
                    if index < builtin_profiles().len() {
                        self.profile_idx = index;
                        self.apply_profile(index);
                    }
                }
                1 => {
                    if activate {
                        self.edit = LineEdit::new(self.spec.targets.clone());
                        self.modal = Modal::Edit {
                            title: "Targets (hosts, CIDR, ranges)".into(),
                            id: "targets".into(),
                        };
                    }
                }
                2 => {
                    if index < ROWS.len() && !matches!(ROWS[index].kind, RowKind::Header) {
                        self.option_idx = index;
                        if activate {
                            self.activate_option();
                        }
                    }
                }
                _ => {}
            },
            Tab::Live | Tab::Results => {
                if pane == 0 || (self.tab == Tab::Live && pane == 1) {
                    if index < self.filtered_hosts().len() {
                        self.host_idx = index;
                        self.port_idx = 0;
                        if activate {
                            self.focus_pane(1);
                        }
                    }
                } else {
                    self.port_idx = index.min(self.current_ports().len().saturating_sub(1));
                }
            }
            Tab::History => {
                if index < self.history.entries.len() {
                    self.history_idx = index;
                    if activate {
                        let e = self.history.entries[index].clone();
                        match persist::load_scan_xml(&e.dir) {
                            Ok(doc) => {
                                self.results = doc;
                                self.select_screen(2);
                                self.host_idx = 0;
                            }
                            Err(e) => self.message("Open failed", e.to_string()),
                        }
                    }
                }
            }
            Tab::Scripts => {
                if pane == 0 {
                    self.script_cat = index.min(CATEGORIES.len());
                    self.script_idx = 0;
                } else {
                    self.script_idx = index.min(self.filtered_scripts().len().saturating_sub(1));
                    if activate {
                        let name = self
                            .filtered_scripts()
                            .get(self.script_idx)
                            .map(|s| s.name.clone());
                        if let Some(name) = name {
                            self.toggle_script(&name);
                        }
                    }
                }
            }
            Tab::Compare => {
                if index < self.history.entries.len() {
                    if pane == 0 {
                        self.compare_left = Some(index)
                    } else if pane == 1 {
                        self.compare_right = Some(index)
                    }
                }
            }
        }
    }
    fn navigation_scroll(&mut self, pane: usize, d: i32) {
        match self.tab {
            Tab::Scan => match pane {
                0 => {
                    self.profile_idx =
                        crate::navigation::step(self.profile_idx, builtin_profiles().len(), d);
                    self.apply_profile(self.profile_idx)
                }
                2 => self.option_idx = fields::next_selectable(self.option_idx, d as isize),
                _ => {}
            },
            Tab::Live if pane == 1 => {
                self.host_idx = (self.host_idx as i32 + d)
                    .clamp(0, self.results.hosts.len().saturating_sub(1) as i32)
                    as usize;
            }
            Tab::Live => {
                self.log_follow = false;
                if d < 0 {
                    self.log_scroll = self.log_scroll.saturating_add(3)
                } else {
                    self.log_scroll = self.log_scroll.saturating_sub(3)
                }
            }
            Tab::Results => {
                if pane == 0 {
                    self.host_idx = (self.host_idx as i32 + d)
                        .max(0)
                        .min(self.filtered_hosts().len().saturating_sub(1) as i32)
                        as usize;
                    self.port_idx = 0;
                } else if self.result_pane == ResultPane::Ports {
                    self.port_idx = (self.port_idx as i32 + d)
                        .max(0)
                        .min(self.current_ports().len().saturating_sub(1) as i32)
                        as usize;
                } else {
                    let i = self.navigation_screen();
                    self.navigation.scroll[i] = (self.navigation.scroll[i] as i32 + d * 3)
                        .max(0)
                        .min(u16::MAX as i32)
                        as u16;
                }
            }
            Tab::History => {
                self.history_idx =
                    crate::navigation::step(self.history_idx, self.history.entries.len(), d)
            }
            Tab::Scripts => {
                if pane == 0 {
                    self.script_cat =
                        crate::navigation::step(self.script_cat, CATEGORIES.len() + 1, d);
                    self.script_idx = 0;
                } else {
                    self.script_idx =
                        crate::navigation::step(self.script_idx, self.filtered_scripts().len(), d)
                }
            }
            Tab::Compare => {
                if pane == 2 {
                    let i = self.navigation_screen();
                    self.navigation.scroll[i] = (self.navigation.scroll[i] as i32 + d * 3)
                        .max(0)
                        .min(u16::MAX as i32)
                        as u16;
                } else {
                    let slot = if pane == 0 {
                        &mut self.compare_left
                    } else {
                        &mut self.compare_right
                    };
                    *slot = Some(crate::navigation::step(
                        slot.unwrap_or(0),
                        self.history.entries.len(),
                        d,
                    ));
                }
            }
        }
    }
    pub fn navigation_mouse(&mut self, event: crossterm::event::MouseEvent) {
        if self.filtering {
            return;
        }
        if !matches!(self.modal, Modal::None) {
            if let Some(intent) = self.navigation.mouse(event) {
                if matches!(
                    intent,
                    crate::navigation::Intent::Command("Confirm" | "Cancel")
                ) {
                    self.dispatch_intent(intent);
                }
            }
            return;
        }
        if self.navigation.open {
            let entries = self.navigation_entries();
            if let Some(intent) = self.navigation.menu_mouse(event, &entries) {
                self.dispatch_intent(intent);
            }
            return;
        }
        if self.commands.open {
            if let Some(action) = self.commands.mouse(event, &self.command_actions()) {
                self.dispatch_intent(action.target);
            }
            return;
        }
        if let Some(intent) = self.navigation.mouse(event) {
            self.dispatch_intent(intent);
        }
    }
}

impl App {
    fn navigation_details_scroll(&mut self, _p: usize, d: i32) {
        let i = self.navigation_screen();
        self.navigation.scroll[i] =
            (self.navigation.scroll[i] as i32 + d * 3).clamp(0, u16::MAX as i32) as u16;
    }
    fn navigation_selector(&mut self, i: usize) {
        if self.tab == Tab::Results {
            self.result_pane = match i {
                0 => ResultPane::Ports,
                1 => ResultPane::Scripts,
                2 => ResultPane::Os,
                _ => ResultPane::Raw,
            };
            self.navigation.scroll[2] = 0;
        }
    }
}

impl App {
    pub fn footer_hints(&self) -> Vec<(&'static str, &'static str)> {
        match self.tab {
            Tab::Scan => match self.scan_pane {
                ScanPane::Profiles => vec![
                    ("Ctrl+G", "review/run"),
                    ("Ctrl+K", "actions"),
                    ("↑/↓", "profile"),
                ],
                ScanPane::Targets => vec![
                    ("Enter", "edit targets"),
                    ("Ctrl+K", "actions"),
                    ("Ctrl+G", "review/run"),
                ],
                ScanPane::Options => vec![
                    ("Enter", "edit/toggle"),
                    ("Ctrl+K", "actions"),
                    ("Ctrl+G", "review/run"),
                ],
            },
            Tab::Live => vec![
                ("Ctrl+X", "cancel"),
                ("Ctrl+K", "actions"),
                ("PgUp/PgDn", "scroll"),
            ],
            Tab::Results => {
                if self.focused_pane() == 0 {
                    vec![("Enter", "inspect"), ("Ctrl+K", "actions"), ("/", "filter")]
                } else {
                    vec![
                        ("←/→", "detail view"),
                        ("Ctrl+K", "actions"),
                        ("e", "export"),
                        ("PgUp/PgDn", "scroll"),
                    ]
                }
            }
            Tab::History => vec![
                ("Enter", "open"),
                ("Ctrl+K", "actions"),
                ("i", "import"),
                ("r", "resume"),
                ("R", "rerun"),
            ],
            Tab::Scripts => {
                if self.focused_pane() == 0 {
                    vec![
                        ("↑/↓", "category"),
                        ("Ctrl+K", "actions"),
                        ("F6", "scripts"),
                    ]
                } else {
                    vec![
                        ("Space", "toggle script"),
                        ("Ctrl+K", "actions"),
                        ("/", "filter"),
                    ]
                }
            }
            Tab::Compare => vec![
                ("↑/↓", "choose/scroll"),
                ("Ctrl+K", "actions"),
                ("F6", "pane"),
            ],
        }
    }
}
