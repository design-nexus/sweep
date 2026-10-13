use crate::app::{App, Modal, ResultPane, ScanPane, Tab};
use crate::export::DiffKind;
use crate::fields::{ROWS, RowKind};
use crate::nmap::profiles::builtin_profiles;
use crate::nmap::scripts::CATEGORIES;
use crate::theme;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, ListItem, Paragraph, Wrap};

pub fn draw(frame: &mut Frame, app: &App) {
    app.navigation.begin(frame.area());
    let area = frame.area();
    frame.render_widget(Block::default().style(theme::bg()), area);

    if area.width < 30 || area.height < 14 {
        frame.render_widget(
            Paragraph::new("sweep · needs 30×14\nResize terminal; q quits"),
            area,
        );
        return;
    }
    let chrome = chrome();
    let area = chrome.shell(frame, area);
    let header_h = crate::aurora::title_height(area.height) + 3;
    let command_h = if area.width >= 80 { 3 } else { 4 };
    let footer_h = if area.height >= 26 { 4 } else { 3 };
    let chunks = Layout::vertical([
        Constraint::Length(header_h),
        Constraint::Min(1),
        Constraint::Length(command_h),
        Constraint::Length(footer_h),
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    let body_block = Block::default().padding(ratatui::widgets::Padding::new(
        2,
        2,
        u16::from(chunks[1].height >= 8),
        0,
    ));
    let body = body_block.inner(chunks[1]);
    match app.tab {
        Tab::Scan => draw_scan(frame, app, body),
        Tab::Live => draw_live(frame, app, body),
        Tab::Results => draw_results(frame, app, body),
        Tab::History => draw_history(frame, app, body),
        Tab::Scripts => draw_scripts(frame, app, body),
        Tab::Compare => draw_compare(frame, app, body),
    }
    draw_command(frame, app, chunks[2]);
    let footer = chrome.footer(frame, chunks[3]);
    draw_status(frame, app, footer);

    if app.filtering {
        draw_prompt(frame, area, "filter", &app.edit.value, app.edit.cursor);
    }
    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(frame, area, app.help_scroll),
        Modal::ConfirmRun => draw_confirm(
            frame,
            area,
            "Launch scan?",
            &format!(
                "{}\n\n{}  ·  Enter/y confirm  Esc/n cancel",
                app.spec.preview_command(),
                if app.spec.needs_root() && !app.nmap.euid_root {
                    "needs root (will try sudo -n)"
                } else {
                    "unprivileged or already root"
                }
            ),
        ),
        Modal::ConfirmQuit => draw_confirm(
            frame,
            area,
            "Quit while a scan is running?",
            "SIGINT will be sent to nmap.\nEnter/y quit  Esc/n stay",
        ),
        Modal::ConfirmDelete => draw_confirm(
            frame,
            area,
            "Delete this history entry?",
            "XML on disk will be removed. Enter/y  Esc/n",
        ),
        Modal::Edit { title, .. } => {
            draw_prompt(frame, area, title, &app.edit.value, app.edit.cursor)
        }
        Modal::Import => draw_prompt(
            frame,
            area,
            "Import nmap XML path",
            &app.edit.value,
            app.edit.cursor,
        ),
        Modal::Export { format } => {
            let kind = match format {
                crate::export::Format::Json => "JSON",
                crate::export::Format::Markdown => "Markdown",
                crate::export::Format::Csv => "CSV",
            };
            draw_prompt(
                frame,
                area,
                &format!("Export {kind} to path"),
                &app.edit.value,
                app.edit.cursor,
            );
        }
        Modal::Message { title, body } => draw_confirm(frame, area, title, body),
    }
    if matches!(
        app.modal,
        Modal::ConfirmRun | Modal::ConfirmQuit | Modal::ConfirmDelete
    ) {
        let popup = centered(area, area.width.saturating_sub(10).min(80), 10);
        app.navigation
            .dialog_buttons(frame, popup, app.navigation_skin());
    }
    app.commands.draw(
        frame,
        &app.command_actions(),
        theme::bg_color(),
        theme::fg(),
        theme::purple(),
        theme::selected().bg.unwrap_or(theme::current()),
    );
    app.draw_navigation(frame);
}

fn chrome() -> crate::aurora::Chrome {
    crate::aurora::Chrome {
        base: theme::bg(),
        muted: theme::muted(),
        accent: theme::title(),
        data: theme::ip(),
        border: Style::default().fg(theme::comment()),
        deep: Style::default().bg(theme::deep()).fg(theme::fg()),
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let [identity, tabs] = Layout::vertical([
        Constraint::Length(crate::aurora::title_height(
            frame.area().height.saturating_sub(2),
        )),
        Constraint::Min(1),
    ])
    .areas(area);
    let state = if app.live.as_ref().is_some_and(|l| l.running()) {
        "● running"
    } else if app.nmap.present() {
        "● ready"
    } else {
        "○ nmap offline"
    };
    chrome().title(
        frame,
        identity,
        "sweep",
        "Network discovery / Nmap",
        state,
        if state.contains("offline") {
            theme::err()
        } else {
            theme::ok()
        },
    );
    app.navigation_bar(frame, tabs);
}

fn draw_command(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .style(Style::default().bg(theme::current()).fg(theme::fg()))
        .padding(ratatui::widgets::Padding::new(2, 2, 1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let cmd = app.spec.preview_command();
    if inner.width >= 75 {
        let [label, command] =
            Layout::horizontal([Constraint::Length(10), Constraint::Min(0)]).areas(inner);
        frame.render_widget(Paragraph::new("COMMAND").style(theme::muted()), label);
        frame.render_widget(
            Paragraph::new(cmd)
                .style(theme::ip())
                .wrap(Wrap { trim: false }),
            command,
        );
    } else {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("COMMAND", theme::muted())),
                Line::from(Span::styled(cmd, theme::ip())),
            ])
            .wrap(Wrap { trim: false }),
            inner,
        );
    }
}
fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let [keys, status] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(crate::navigation::shortcuts(
            &app.footer_hints(),
            keys.width,
            theme::title(),
            theme::muted(),
        ))
        .style(chrome().deep),
        keys,
    );
    let area = status;
    let running = app.live.as_ref().is_some_and(|l| l.running());
    let state = if running {
        Span::styled(" RUNNING ", theme::warn().add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" READY ", theme::ok().add_modifier(Modifier::BOLD))
    };
    let root = if app.spec.needs_root() {
        Span::styled(" needs root ", theme::warn())
    } else {
        Span::styled(" no root ", theme::muted())
    };
    let line = Line::from(vec![
        state,
        Span::styled(format!(" {} ", app.status), theme::muted()),
        root,
    ]);
    frame.render_widget(Paragraph::new(line).style(chrome().deep), area);
}

fn draw_scan(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 70 {
        match app.scan_pane {
            ScanPane::Profiles => [area, Rect::default(), Rect::default()],
            ScanPane::Targets => [Rect::default(), area, Rect::default()],
            ScanPane::Options => [Rect::default(), Rect::default(), area],
        }
    } else {
        let [profiles, _gutter, content] = Layout::horizontal([
            Constraint::Length(if area.width >= 100 { 32 } else { 24 }),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .areas(area);
        let [targets, _gap, options] = Layout::vertical([
            Constraint::Length(if area.height >= 15 { 7 } else { 5 }),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(content);
        [profiles, targets, options]
    };
    for (i, rect) in cols.iter().enumerate() {
        app.navigation.pane(*rect, i);
    }
    if !cols[0].is_empty() {
        let border = Style::default().fg(if app.scan_pane == ScanPane::Profiles {
            theme::purple()
        } else {
            theme::comment()
        });
        let sidebar = crate::aurora::sidebar(frame, cols[0], border);
        let heading_h = sidebar.height.min(if sidebar.height >= 8 { 2 } else { 1 });
        let description_h = if sidebar.height >= 12 { 3 } else { 0 };
        let gap_h = u16::from(sidebar.height >= 12);
        let list_h = sidebar
            .height
            .saturating_sub(heading_h + description_h + gap_h)
            .max(1);
        let profiles = builtin_profiles();
        let row_h = if list_h as usize >= profiles.len() * 2 {
            2
        } else {
            1
        };
        let visible = (list_h / row_h).max(1).min(profiles.len() as u16) as usize;
        let [heading, list, _gap, description, _space] = Layout::vertical([
            Constraint::Length(heading_h),
            Constraint::Length(list_h),
            Constraint::Length(gap_h),
            Constraint::Length(description_h),
            Constraint::Min(0),
        ])
        .areas(sidebar);
        frame.render_widget(
            Paragraph::new("Scan profiles").style(theme::title()),
            heading,
        );
        let start = window_start(app.profile_idx, visible);
        app.navigation.rows(list, 0, start, row_h, visible);
        let mut items = Vec::new();
        for (i, profile) in profiles.iter().enumerate().skip(start).take(visible) {
            let style = if i == app.profile_idx {
                theme::selected()
            } else {
                theme::bg()
            };
            let line = Line::from(Span::styled(
                format!(
                    "{}{}",
                    if i == app.profile_idx { "▸ " } else { "  " },
                    profile.name
                ),
                style,
            ));
            items.push(ratatui::widgets::ListItem::new(if row_h == 2 {
                vec![line, Line::from("")]
            } else {
                vec![line]
            }));
        }
        let mut state = ratatui::widgets::ListState::default();
        state.select(Some(app.profile_idx.saturating_sub(start)));
        frame.render_stateful_widget(
            ratatui::widgets::List::new(items).highlight_style(theme::selected()),
            list,
            &mut state,
        );
        frame.render_widget(
            Paragraph::new(profiles[app.profile_idx].description)
                .style(theme::muted())
                .wrap(Wrap { trim: false }),
            description,
        );
    }
    if !cols[1].is_empty() {
        let target_area = cols[1];
        let block = Block::bordered()
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(if app.scan_pane == ScanPane::Targets {
                theme::purple()
            } else {
                theme::comment()
            }))
            .padding(ratatui::widgets::Padding::horizontal(1));
        let inner = block.inner(target_area);
        frame.render_widget(block, target_area);
        app.navigation
            .hit(inner, crate::navigation::Intent::Row(1, 0));
        let mut lines = vec![
            Line::from(Span::styled(
                format!(
                    "Targets{}",
                    if app.profile_dirty { " · edited" } else { "" }
                ),
                theme::title(),
            )),
            Line::from(Span::styled(
                if app.spec.targets.is_empty() {
                    "Enter to set hosts / CIDR / ranges"
                } else {
                    &app.spec.targets
                },
                theme::ip(),
            )),
        ];
        if inner.height >= 4 {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Hosts, CIDR blocks, or address ranges",
                theme::muted(),
            )));
            lines.push(Line::from(Span::styled(
                format!("profile: {}", app.profile_label()),
                theme::script(),
            )));
        }
        if inner.height < 2 {
            lines.remove(0);
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
    draw_options(frame, app, cols[2]);
}

fn draw_options(frame: &mut Frame, app: &App, area: Rect) {
    if app.scan_pane != ScanPane::Options {
        let spec = &app.spec;
        let ports = if spec.fast_ports {
            "Top 100".into()
        } else if let Some(top) = spec.top_ports {
            format!("Top {top}")
        } else {
            spec.ports.clone().unwrap_or_else(|| "Default ports".into())
        };
        let timing = spec
            .timing
            .map(|t| format!("T{t}"))
            .unwrap_or_else(|| "Default".into());
        let toggle = |enabled| if enabled { "on" } else { "off" };
        let privileges = if spec.needs_root() {
            "root required"
        } else {
            "no root required"
        };
        let rows = [
            ("Port selection", ports),
            ("Timing", timing),
            ("Service detection", toggle(spec.version_detection).into()),
            ("OS detection", toggle(spec.os_detection).into()),
            ("Privileges", privileges.into()),
        ];
        let mut lines = vec![
            Line::from(Span::styled("Scan options", theme::title())),
            Line::from(""),
        ];
        for (label, value) in rows {
            let pad = (area.width as usize)
                .saturating_sub(label.len() + value.len())
                .max(2);
            let style = if label == "Privileges" && !spec.needs_root() {
                theme::ok()
            } else if value == "off" {
                theme::muted()
            } else {
                theme::ip()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{label}{}", " ".repeat(pad)), theme::muted()),
                Span::styled(value, style),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("(F6)", theme::title()),
            Span::styled(
                " edits settings · review command before launch",
                theme::muted(),
            ),
        ]));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
        return;
    }
    let inner_h = area.height.saturating_sub(2) as usize;
    let sel = app.option_idx;
    let start = if sel >= inner_h { sel + 1 - inner_h } else { 0 };
    app.navigation.rows(
        Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(2),
        ),
        2,
        start,
        1,
        ROWS.len().saturating_sub(start),
    );
    let mut lines = Vec::new();
    for (i, row) in ROWS.iter().enumerate().skip(start) {
        if lines.len() >= inner_h {
            break;
        }
        if row.kind == RowKind::Header {
            lines.push(Line::from(Span::styled(
                format!(" ▸ {}", row.label),
                theme::title(),
            )));
            continue;
        }
        let val = app.option_value(row);
        let style = if i == sel && app.scan_pane == ScanPane::Options {
            theme::selected()
        } else {
            theme::bg()
        };
        let mark = if i == sel { "▸" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(format!("{mark} {:<26} ", row.label), style),
            Span::styled(val, if i == sel { style } else { theme::ok() }),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines).block(pane(
            " options  space/enter ",
            app.scan_pane == ScanPane::Options,
        )),
        area,
    );
}

fn draw_live(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Min(1), Constraint::Length(36)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(cols[0]);

    let (label, ratio) = if let Some(f) = &app.results.finished {
        (format!("done {}s", f.elapsed), 1.0)
    } else if app.live.as_ref().is_some_and(|l| l.running()) {
        let n = app.results.hosts.len();
        (
            format!(
                "{}  hosts so far {}  up {}",
                app.live
                    .as_ref()
                    .map(|l| l.stats_line.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("scanning…"),
                n,
                app.results.hosts_up()
            ),
            0.15,
        )
    } else {
        ("no live scan".into(), 0.0)
    };
    let gauge = Gauge::default()
        .block(
            Block::bordered()
                .border_style(Style::default().fg(theme::comment()))
                .title(" progress "),
        )
        .gauge_style(Style::default().fg(theme::pink()).bg(theme::current()))
        .ratio(ratio)
        .label(label);
    frame.render_widget(gauge, rows[0]);

    let log: Vec<Line> = app
        .live
        .as_ref()
        .map(|l| l.log.iter().map(|s| colorize_log(s)).collect())
        .unwrap_or_else(|| {
            vec![Line::from(Span::styled(
                "Start a scan from the Scan tab (Ctrl-G).",
                theme::muted(),
            ))]
        });
    let scroll = if app.log_follow { 0 } else { app.log_scroll };
    frame.render_widget(
        Paragraph::new(log)
            .block(pane(" nmap output ", app.focused_pane() == 0))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        rows[1],
    );

    let mut hosts = vec![Line::from(Span::styled("discovered hosts", theme::title()))];
    for h in &app.results.hosts {
        hosts.push(Line::from(vec![
            Span::styled(format!("{:<16} ", h.primary_ip()), theme::ip()),
            Span::styled(h.hostname(), theme::hostname()),
            Span::styled(format!("  {} open", h.open_ports().count()), theme::ok()),
        ]));
    }
    if app.results.hosts.is_empty() {
        hosts.push(Line::from(Span::styled("waiting…", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(hosts).block(pane(" hosts ", app.focused_pane() == 1)),
        cols[1],
    );
    app.navigation.text_rows(
        frame,
        cols[1],
        1,
        &app.results
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (i, h.primary_ip().to_string()))
            .collect::<Vec<_>>(),
    );
}

fn colorize_log(s: &str) -> Line<'static> {
    let style = if s.contains(" open ") || s.starts_with("Nmap scan report") {
        theme::ok()
    } else if s.contains("filtered") || s.contains("Warning") {
        theme::warn()
    } else if s.contains("failed") || s.contains("error") || s.contains("down") {
        theme::err()
    } else if s.contains("Stats:") || s.contains("Timing:") {
        theme::script()
    } else {
        Style::default().fg(theme::fg())
    };
    Line::from(Span::styled(s.to_string(), style))
}

fn draw_results(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Length(34), Constraint::Min(1)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    let hosts = app.filtered_hosts();
    let mut lines = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let style = if i == app.host_idx {
            theme::selected()
        } else {
            theme::port_state(&h.status)
        };
        lines.push(Line::from(Span::styled(
            format!(
                "{:<16} {:<12} {:>3} open",
                h.primary_ip(),
                truncate(h.hostname(), 12),
                h.open_ports().count()
            ),
            style,
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no hosts — run a scan or import XML (History, i)",
            theme::muted(),
        )));
    }
    if !cols[0].is_empty() {
        let block = pane(" Hosts · (Enter) inspect ", app.focused_pane() == 0);
        let inner = block.inner(cols[0]);
        frame.render_widget(block, cols[0]);
        app.navigation.list(
            frame,
            inner,
            0,
            lines
                .into_iter()
                .map(ratatui::widgets::ListItem::new)
                .collect(),
            app.host_idx,
            app.navigation_skin(),
        );
    }

    let right = Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).split(cols[1]);
    let panes = ["Ports", "Scripts", "OS / traceroute", "Raw XML"];
    let idx = match app.result_pane {
        ResultPane::Ports => 0,
        ResultPane::Scripts => 1,
        ResultPane::Os => 2,
        ResultPane::Raw => 3,
    };
    let tabline = Line::from(
        panes
            .iter()
            .enumerate()
            .flat_map(|(i, t)| {
                let style = if i == idx {
                    theme::accent()
                } else {
                    theme::muted()
                };
                [Span::styled(format!(" {t} "), style), Span::raw(" ")]
            })
            .collect::<Vec<_>>(),
    );
    frame.render_widget(Paragraph::new(tabline), right[0]);
    let mut x = right[0].x;
    for label in panes {
        let width = (unicode_width::UnicodeWidthStr::width(label) + 3) as u16;
        app.navigation.hit(
            Rect::new(
                x,
                right[0].y,
                width.min(right[0].right().saturating_sub(x)),
                1,
            ),
            crate::navigation::Intent::Command(match label {
                "Ports" => "Result ports",
                "Scripts" => "Result scripts",
                "OS / traceroute" => "Result OS",
                _ => "Result XML",
            }),
        );
        x = x.saturating_add(width);
    }

    match app.result_pane {
        ResultPane::Ports => {
            let mut rows = vec![Line::from(Span::styled(
                format!(
                    "{:<6} {:<6} {:<12} {:<14} {}",
                    "PORT", "PROTO", "STATE", "SERVICE", "VERSION"
                ),
                theme::muted(),
            ))];
            for (i, p) in app.current_ports().iter().enumerate() {
                let style = if i == app.port_idx {
                    theme::selected()
                } else {
                    theme::port_state(&p.state)
                };
                rows.push(Line::from(Span::styled(
                    format!(
                        "{:<6} {:<6} {:<12} {:<14} {} {}",
                        p.portid, p.protocol, p.state, p.service, p.product, p.version
                    ),
                    style,
                )));
            }
            if rows.len() == 1 {
                rows.push(Line::from(Span::styled(
                    "no ports (o toggles closed/filtered)",
                    theme::muted(),
                )));
            }
            let block = pane(
                " Ports · (o) closed · (e/m/c) export ",
                app.focused_pane() == 1,
            );
            let inner = block.inner(right[1]);
            frame.render_widget(block, right[1]);
            let [heading, list] =
                Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
            frame.render_widget(Paragraph::new(rows.remove(0)), heading);
            app.navigation.list(
                frame,
                list,
                1,
                rows.into_iter().map(ListItem::new).collect(),
                app.port_idx,
                app.navigation_skin(),
            );
        }
        ResultPane::Scripts => {
            let mut lines = Vec::new();
            if let Some(h) = app.current_host() {
                for p in &h.ports {
                    for s in &p.scripts {
                        lines.push(Line::from(Span::styled(
                            format!("{}/{}  {}", p.portid, p.protocol, s.id),
                            theme::script(),
                        )));
                        for l in s.output.lines() {
                            lines.push(Line::from(Span::styled(format!("  {l}"), theme::muted())));
                        }
                    }
                }
                for s in &h.host_scripts {
                    lines.push(Line::from(Span::styled(&s.id, theme::script())));
                    for l in s.output.lines() {
                        lines.push(Line::from(Span::styled(format!("  {l}"), theme::muted())));
                    }
                }
            }
            if lines.is_empty() {
                lines.push(Line::from(Span::styled("no script output", theme::muted())));
            }
            frame.render_widget(
                Paragraph::new(lines)
                    .scroll((app.navigation.scroll[app.navigation_screen()], 0))
                    .block(pane(" scripts ", app.focused_pane() == 1)),
                right[1],
            );
        }
        ResultPane::Os => {
            let mut lines = Vec::new();
            if let Some(h) = app.current_host() {
                lines.push(Line::from(vec![
                    Span::styled("status ", theme::muted()),
                    Span::styled(&h.status, theme::port_state(&h.status)),
                    Span::styled(format!("  ({})", h.reason), theme::muted()),
                ]));
                for a in &h.addresses {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "{} {} {}",
                            a.addrtype,
                            a.addr,
                            a.vendor.clone().unwrap_or_default()
                        ),
                        theme::ip(),
                    )));
                }
                for m in &h.os_matches {
                    lines.push(Line::from(Span::styled(
                        format!("{} ({}%) {} {}", m.name, m.accuracy, m.vendor, m.osfamily),
                        theme::script(),
                    )));
                }
                if let Some(d) = &h.distance {
                    lines.push(Line::from(Span::styled(
                        format!("distance {d}"),
                        theme::muted(),
                    )));
                }
                for hop in &h.hops {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "ttl {}  {}  {} ms  {}",
                            hop.ttl, hop.ipaddr, hop.rtt, hop.host
                        ),
                        theme::hostname(),
                    )));
                }
            }
            if lines.is_empty() {
                lines.push(Line::from(Span::styled("no host selected", theme::muted())));
            }
            frame.render_widget(
                Paragraph::new(lines)
                    .scroll((app.navigation.scroll[app.navigation_screen()], 0))
                    .block(pane(" os / traceroute ", app.focused_pane() == 1)),
                right[1],
            );
        }
        ResultPane::Raw => {
            let raw = app
                .current_host()
                .map(|h| h.raw.as_str())
                .unwrap_or("no host");
            frame.render_widget(
                Paragraph::new(raw)
                    .scroll((app.navigation.scroll[app.navigation_screen()], 0))
                    .wrap(Wrap { trim: false })
                    .block(pane(" raw xml ", app.focused_pane() == 1)),
                right[1],
            );
        }
    }
    if app.result_pane != ResultPane::Ports {
        app.navigation.details(right[1], 1);
    }
}

fn draw_history(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        "Enter open   R re-run   r resume   d delete   i import XML",
        theme::muted(),
    ))];
    for (i, e) in app.history.entries.iter().enumerate() {
        let style = if i == app.history_idx {
            theme::selected()
        } else {
            match e.status.as_str() {
                "complete" => theme::ok(),
                "failed" => theme::err(),
                "interrupted" | "running" => theme::warn(),
                _ => theme::bg(),
            }
        };
        lines.push(Line::from(Span::styled(
            format!(
                "{}  {:<12}  {:>3} up  {}",
                e.started.format("%Y-%m-%d %H:%M"),
                e.status,
                e.hosts_up,
                truncate(&e.command, area.width.saturating_sub(36) as usize)
            ),
            style,
        )));
    }
    if app.history.entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "no saved scans yet",
            theme::muted(),
        )));
    }
    let block = pane(" History · (Enter) open · (i) import ", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [header, list] =
        Layout::vertical([Constraint::Length(1.min(inner.height)), Constraint::Min(0)])
            .areas(inner);
    let heading = if lines.is_empty() {
        Line::from("")
    } else {
        lines.remove(0)
    };
    frame.render_widget(Paragraph::new(heading), header);
    app.navigation.list(
        frame,
        list,
        0,
        lines
            .into_iter()
            .map(ratatui::widgets::ListItem::new)
            .collect(),
        app.history_idx,
        app.navigation_skin(),
    );
}

fn draw_scripts(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Length(22), Constraint::Min(1)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    let mut cats = vec![Line::from(Span::styled(
        if app.script_cat == 0 {
            "▸ all"
        } else {
            "  all"
        },
        if app.script_cat == 0 {
            theme::selected()
        } else {
            theme::muted()
        },
    ))];
    for (i, c) in CATEGORIES.iter().enumerate() {
        let sel = app.script_cat == i + 1;
        cats.push(Line::from(Span::styled(
            format!("{} {c}", if sel { "▸" } else { " " }),
            if sel {
                theme::selected()
            } else {
                theme::muted()
            },
        )));
    }
    frame.render_widget(
        Paragraph::new(cats).block(pane(" Categories ", app.focused_pane() == 0)),
        cols[0],
    );

    let list = app.filtered_scripts();
    let selected: Vec<String> = app
        .spec
        .scripts
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let inner_h = cols[1].height.saturating_sub(2) as usize;
    let sel = if list.is_empty() {
        0
    } else {
        app.script_idx.min(list.len() - 1)
    };
    let start = window_start(sel, inner_h);
    let mut lines = Vec::new();
    for (i, s) in list.iter().enumerate().skip(start) {
        if lines.len() >= inner_h {
            break;
        }
        let on = selected.iter().any(|x| x == &s.name);
        let mark = if on { "[x]" } else { "[ ]" };
        let style = if i == sel {
            theme::selected()
        } else if on {
            theme::ok()
        } else {
            theme::bg()
        };
        lines.push(Line::from(Span::styled(
            format!("{mark} {:<28} {}", s.name, s.categories.join(",")),
            style,
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no scripts match", theme::muted())));
    }
    let title = if list.is_empty() {
        " NSE  space toggle  / filter ".to_string()
    } else {
        format!(" NSE {}/{}  space toggle  / filter ", sel + 1, list.len())
    };
    frame.render_widget(
        Paragraph::new(lines).block(pane(&title, app.focused_pane() == 1)),
        cols[1],
    );
    app.navigation.rows(
        cols[0].inner(ratatui::layout::Margin::new(1, 1)),
        0,
        0,
        1,
        CATEGORIES.len() + 1,
    );
    app.navigation.text_rows(
        frame,
        cols[1],
        1,
        &app.filtered_scripts()
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.name.clone()))
            .collect::<Vec<_>>(),
    );
}

fn draw_compare(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        let mut panes = [Rect::default(); 3];
        panes[app.focused_pane().min(2)] = area;
        panes
    } else {
        Layout::horizontal([
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Percentage(40),
        ])
        .areas(area)
    };
    for (i, rect) in cols.iter().enumerate() {
        app.navigation.pane(*rect, i);
    }
    draw_compare_side(frame, app, cols[0], 0, app.compare_left, " A (older) ");
    draw_compare_side(frame, app, cols[1], 1, app.compare_right, " B (newer) ");
    let mut lines = Vec::new();
    for d in app.diff_lines() {
        let style = match d.kind {
            DiffKind::Added => theme::ok(),
            DiffKind::Removed => theme::err(),
            DiffKind::Changed => theme::warn(),
            DiffKind::Same => theme::muted(),
        };
        lines.push(Line::from(Span::styled(d.text, style)));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.navigation.scroll[app.navigation_screen()], 0))
            .block(pane(" diff ", app.focused_pane() == 2)),
        cols[2],
    );
}

fn draw_compare_side(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    focus: u8,
    selected: Option<usize>,
    title: &str,
) {
    let mut lines = Vec::new();
    for (i, e) in app.history.entries.iter().enumerate() {
        let style = if selected == Some(i) {
            theme::selected()
        } else {
            theme::muted()
        };
        lines.push(Line::from(Span::styled(
            format!(
                "{} {}",
                e.started.format("%m-%d %H:%M"),
                truncate(&e.targets, 16)
            ),
            style,
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no history", theme::muted())));
    }
    let block = pane(title, app.focused_pane() == focus as usize);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.navigation.list(
        frame,
        inner,
        focus as usize,
        lines
            .into_iter()
            .map(ratatui::widgets::ListItem::new)
            .collect(),
        selected.unwrap_or(0),
        app.navigation_skin(),
    );
}

fn draw_help(frame: &mut Frame, area: Rect, scroll: u16) {
    let text = HELP;
    let popup = centered(
        area,
        area.width.saturating_sub(8).min(90),
        area.height.saturating_sub(4).min(28),
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .style(theme::bg())
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::bordered()
                    .title(Span::styled(" help ", theme::title()))
                    .border_style(Style::default().fg(theme::purple())),
            ),
        popup,
    );
}

fn draw_confirm(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let popup = centered(area, area.width.saturating_sub(10).min(80), 10);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(body)
            .style(theme::bg())
            .wrap(Wrap { trim: false })
            .alignment(Alignment::Left)
            .block(
                Block::bordered()
                    .title(Span::styled(format!(" {title} "), theme::title()))
                    .border_style(Style::default().fg(theme::pink())),
            ),
        popup,
    );
}

fn draw_prompt(frame: &mut Frame, area: Rect, title: &str, value: &str, cursor: usize) {
    let popup = centered(area, area.width.saturating_sub(10).min(80), 5);
    frame.render_widget(Clear, popup);
    let mut shown = value.to_string();
    let byte = value
        .char_indices()
        .nth(cursor)
        .map(|(i, _)| i)
        .unwrap_or(value.len());
    shown.insert(byte, '▌');
    let cursor_column = unicode_width::UnicodeWidthStr::width(&shown[..byte]);
    let offset = cursor_column
        .saturating_sub(popup.width.saturating_sub(4) as usize)
        .min(u16::MAX as usize) as u16;

    frame.render_widget(
        Paragraph::new(shown)
            .scroll((0, offset))
            .style(theme::bg().fg(theme::yellow()))
            .block(
                Block::bordered()
                    .title(Span::styled(format!(" {title} "), theme::title()))
                    .border_style(Style::default().fg(theme::cyan())),
            ),
        popup,
    );
}

fn pane(title: &str, active: bool) -> Block<'_> {
    Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(Span::styled(
            title,
            if active {
                theme::accent()
            } else {
                theme::muted()
            },
        ))
        .border_style(Style::default().fg(if active {
            theme::pink()
        } else {
            theme::comment()
        }))
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn window_start(sel: usize, height: usize) -> usize {
    if height == 0 || sel < height {
        0
    } else {
        sel + 1 - height
    }
}

fn truncate(s: &str, n: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if s.width() <= n {
        return s.to_owned();
    }
    if n == 0 {
        return String::new();
    }
    let mut text = String::new();
    let mut width = 0;
    for c in s.chars() {
        let next = c.width().unwrap_or(0);
        if width + next > n - 1 {
            break;
        }
        text.push(c);
        width += next;
    }
    text.push('…');
    text
}

const HELP: &str = r#"Sweep — Aurora Nmap frontend

Tabs          1 Scan  2 Live  3 Results  4 History  5 Scripts  6 Compare
Tab/S-Tab     screens    F6/S-F6 panes    F2 Navigate          ? this help          q quit

Scan builder
  j/k         move          space/enter toggle or edit
  Enter       set targets   y yank command
  Ctrl-G      run (confirm) extra args are split, never passed to a shell

Live
  j/k scroll log    G follow tail    Ctrl-X cancel (then SIGKILL after 3s)

Results
  h/l hosts    j/k ports    [ ] detail pane
  o  show closed/filtered   / filter
  e JSON   m Markdown   c CSV

History
  Enter open XML    R re-run    r --resume    d delete    i import

Scripts
  h/l category    space add/remove --script    / filter

Root
  SYN/UDP/OS/-A need privileges. If you are not root, sudo -n nmap is tried.
  Run `sudo -v` first, or start sweep via sudo.

Only scan networks you own or have permission to test."#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;

    #[test]
    fn window_start_keeps_selection_visible() {
        assert_eq!(window_start(0, 10), 0);
        assert_eq!(window_start(9, 10), 0);
        assert_eq!(window_start(10, 10), 1);
        assert_eq!(window_start(25, 10), 16);
        assert_eq!(window_start(3, 0), 0);
    }

    #[test]
    fn draw_fits_small_and_large_terminals() {
        let app = App::new().unwrap();
        for (w, h) in [(80, 24), (120, 36), (40, 12)] {
            let backend = ratatui::backend::TestBackend::new(w, h);
            let mut term = ratatui::Terminal::new(backend).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
        }
    }
}

#[cfg(test)]
mod aurora_audit {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn commands() -> KeyEvent {
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL)
    }
    fn fixture(dir: &std::path::Path) -> App {
        let paths = crate::persist::Paths {
            data: dir.into(),
            config: dir.into(),
            scans: dir.join("scans"),
            history: dir.join("history.toml"),
        };
        let mut app = App::with_paths(paths).unwrap();
        app.apply_cli(
            Some("192.168.1.0/24".into()),
            Some("Quick scan".into()),
            None,
            vec![],
        )
        .unwrap();
        app.scan_pane = ScanPane::Profiles;
        app
    }

    #[tokio::test]
    async fn security_themes_keep_every_screen_and_pane_navigable() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        for id in ["crimson", "aurora"] {
            let action = app
                .command_actions()
                .into_iter()
                .find(|a| {
                    a.label
                        == if id == "crimson" {
                            "Crimson theme"
                        } else {
                            "Aurora theme"
                        }
                })
                .expect("theme action");
            assert_eq!(action.target, crate::navigation::Intent::Theme(id));
            app.dispatch_intent(action.target);
            let screens = app
                .navigation_entries()
                .iter()
                .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
                .count();
            for screen in 0..screens {
                app.select_screen(screen);
                for pane in 0..app.pane_names().len() {
                    app.focus_pane(pane);
                    for &(w, h) in &crate::audit::SIZES[..4] {
                        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                        terminal.draw(|f| draw(f, &app)).unwrap();
                        let buffer = terminal.backend().buffer();
                        assert!(crate::audit::text(buffer).contains("(F2)"));
                        crate::audit::verify_footer(buffer);
                        crate::audit::capture(
                            "sweep",
                            &format!("{id}-screen{screen}-pane{pane}"),
                            buffer,
                        );
                    }
                }
            }
        }
    }
    #[tokio::test]
    async fn common_navigation_contract_preserves_focus_and_drafts() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.focus_pane(0);
        if app.navigation_editing() {
            let _ = app.handle_key(key(KeyCode::Esc));
        }
        let screen = app.navigation_screen();
        let pane = app.focused_pane();
        let _ = app.handle_key(key(KeyCode::Tab));
        assert_eq!(
            app.navigation_screen(),
            crate::navigation::step(
                screen,
                app.navigation_entries()
                    .iter()
                    .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
                    .count(),
                1
            )
        );
        if app.navigation_editing() {
            let _ = app.handle_key(key(KeyCode::Esc));
        }
        let _ = app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.navigation_screen(), screen);
        let _ = app.handle_key(key(KeyCode::F(6)));
        assert_eq!(
            app.focused_pane(),
            crate::navigation::step(pane, app.pane_names().len(), 1)
        );
        let _ = app.handle_key(KeyEvent::new(KeyCode::F(6), KeyModifiers::SHIFT));
        assert_eq!(app.focused_pane(), pane);
        let _ = app.handle_key(key(KeyCode::F(2)));
        assert!(app.navigation.open);
        let _ = app.handle_key(key(KeyCode::Char('1')));
        assert!(!app.navigation.open);
        assert_eq!(app.navigation_screen(), 0);
        app.select_screen(screen);
        let _ = app.handle_key(key(KeyCode::F(2)));
        assert!(app.navigation.open);

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        assert!(crate::audit::text(terminal.backend().buffer()).contains("Navigate"));
        let _ = app.handle_key(key(KeyCode::Esc));
        assert!(!app.navigation.open);
        terminal.draw(|f| draw(f, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut hit = None;
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width.saturating_sub(3) {
                if buffer[(x, y)].symbol() == "("
                    && buffer[(x + 1, y)].symbol() == "F"
                    && buffer[(x + 2, y)].symbol() == "2"
                {
                    hit = Some((x, y));
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }
        let (x, y) = hit.expect("visible clickable navigation");
        app.navigation_mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        });
        assert!(app.navigation.open);
        let _ = app.handle_key(key(KeyCode::Esc));

        let _ = app.handle_key(commands());
        assert!(app.commands.open);
        let _ = app.handle_key(key(KeyCode::Esc));
    }
    #[tokio::test]
    async fn all_screens_and_focus_targets_fit_the_navigation_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        let screens = app
            .navigation_entries()
            .iter()
            .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
            .count();
        for screen in 0..screens {
            app.select_screen(screen);
            for pane in 0..app.pane_names().len() {
                app.focus_pane(pane);
                for &(w, h) in &crate::audit::SIZES[..4] {
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                    terminal.draw(|f| draw(f, &app)).unwrap();
                    let buffer = terminal.backend().buffer();
                    assert!(
                        crate::audit::text(buffer).contains("(F2)"),
                        "screen {screen} pane {pane} must expose navigation at {w}x{h}"
                    );
                    crate::audit::verify_footer(buffer);
                    crate::audit::capture(
                        "sweep",
                        &format!("navigation-screen{screen}-pane{pane}"),
                        buffer,
                    );
                    let before = app.navigation_screen();
                    app.navigation_mouse(crossterm::event::MouseEvent {
                        kind: crossterm::event::MouseEventKind::Down(
                            crossterm::event::MouseButton::Left,
                        ),
                        column: w + 1,
                        row: h + 1,
                        modifiers: KeyModifiers::NONE,
                    });
                    assert_eq!(app.navigation_screen(), before);
                }
            }
        }
    }
    #[test]
    fn scan_preview_is_visible_and_edit_owns_commands() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        let mut term = Terminal::new(TestBackend::new(60, 20)).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let text = crate::audit::text(term.backend().buffer());
        assert!(text.contains(&app.spec.preview_command()), "{text}");
        app.scan_pane = ScanPane::Targets;
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(app.modal, Modal::Edit { .. }));
        app.handle_key(commands());
        assert!(!app.commands.open);
        assert!(app.pending_start.is_none());
    }
    #[test]
    #[ignore = "interactive mock fixture for visual QA"]
    fn live_preview() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        if let Ok(id) = std::env::var("TUI_PREVIEW_THEME") {
            crate::theme::set(&id);
        }
        match std::env::var("AURORA_NAV_PREVIEW").as_deref() {
            Ok("confirm") => {
                app.modal = Modal::ConfirmRun;
            }
            Ok("menu") => app.navigation.toggle(),
            Ok("actions") => app.commands.open = true,
            Ok("focused") => app.focus_pane(1),
            _ => {}
        }
        crate::audit::live_preview(
            &mut app,
            |f, a| draw(f, a),
            |a, k| {
                if matches!(
                    k.code,
                    KeyCode::F(2)
                        | KeyCode::F(6)
                        | KeyCode::Tab
                        | KeyCode::BackTab
                        | KeyCode::Down
                        | KeyCode::Up
                        | KeyCode::Esc
                        | KeyCode::Char('1'..='9')
                ) {
                    a.handle_key(k);
                }
            },
        );
    }
    #[test]
    fn profiles_use_available_height_and_keep_selection_visible() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| draw(f, &app)).unwrap();
        let text = crate::audit::text(term.backend().buffer());
        for profile in builtin_profiles() {
            assert!(
                text.contains(profile.name),
                "missing profile {}",
                profile.name
            );
        }
        app.profile_idx = builtin_profiles().len() - 1;
        for (w, h) in [(100, 30), (80, 24), (60, 20)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            assert!(
                crate::audit::text(term.backend().buffer()).contains("▸ Slow comprehensive"),
                "selected profile disappeared at {w}x{h}"
            );
        }
    }
    #[test]
    fn responsive_render_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        // One terminal exercises shrink/grow transitions, rather than independent initial frames.
        let mut resizing = Terminal::new(TestBackend::new(120, 40)).unwrap();
        for &(w, h) in &[
            (120, 40),
            (60, 20),
            (80, 24),
            (30, 10),
            (100, 30),
            (120, 40),
        ] {
            resizing.backend_mut().resize(w, h);
            resizing.draw(|f| draw(f, &app)).unwrap();
            assert_eq!(resizing.backend().buffer().area.width, w);
        }
        for &(w, h) in crate::audit::SIZES {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let buffer = term.backend().buffer();
            if w >= 30 && h >= 14 {
                assert!(
                    buffer
                        .content
                        .iter()
                        .any(|cell| matches!(cell.symbol(), "█" | "▀" | "▄")
                            && cell.fg == crate::theme::pink())
                );
            }
            crate::audit::verify_footer(buffer);
            crate::audit::capture("sweep", "main", buffer);
        }
        app.scan_pane = ScanPane::Options;
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            crate::audit::capture("sweep", "focused", term.backend().buffer());
        }
        app.handle_key(commands());
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let buffer = term.backend().buffer();
            assert!(crate::audit::text(buffer).contains("Actions"));
            crate::audit::capture("sweep", "actions", buffer);
        }
        app.commands.open = false;
        app.spec.targets.clear();
        app.results = Default::default();
        for tab in Tab::all() {
            app.tab = tab;
            for &(w, h) in &crate::audit::SIZES[..4] {
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| draw(f, &app)).unwrap();
                crate::audit::verify_footer(term.backend().buffer());
                crate::audit::capture("sweep", "offline", term.backend().buffer());
            }
        }
    }
}

#[cfg(test)]
mod unicode_regressions {
    use super::*;
    #[test]
    fn labels_fit_display_columns() {
        use unicode_width::UnicodeWidthStr;
        for width in 0..10 {
            assert!(truncate("你好 🦀 cafe\u{301}", width).width() <= width);
        }
    }
}
