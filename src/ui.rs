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
use ratatui::widgets::{Block, Clear, Gauge, Paragraph, Tabs, Wrap};

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(theme::bg()), area);

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    match app.tab {
        Tab::Scan => draw_scan(frame, app, chunks[1]),
        Tab::Live => draw_live(frame, app, chunks[1]),
        Tab::Results => draw_results(frame, app, chunks[1]),
        Tab::History => draw_history(frame, app, chunks[1]),
        Tab::Scripts => draw_scripts(frame, app, chunks[1]),
        Tab::Compare => draw_compare(frame, app, chunks[1]),
    }
    draw_command(frame, app, chunks[2]);
    draw_status(frame, app, chunks[3]);

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
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::all()
        .into_iter()
        .map(|t| Line::from(Span::styled(format!(" {} ", t.title()), theme::muted())))
        .collect();
    let selected = Tab::all().iter().position(|t| *t == app.tab).unwrap_or(0);
    let nmap = app.nmap.version_short();
    let root = if app.nmap.euid_root { "root" } else { "user" };
    let tabs = Tabs::new(titles)
        .select(selected)
        .highlight_style(theme::accent())
        .block(
            Block::bordered()
                .border_style(Style::default().fg(theme::COMMENT))
                .title(Span::styled(
                    format!(" Nexus-Map  {nmap}  {root}  Dracula "),
                    theme::title(),
                )),
        );
    frame.render_widget(tabs, area);
}

fn draw_command(frame: &mut Frame, app: &App, area: Rect) {
    let cmd = app.spec.preview_command();
    let p = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(cmd, theme::flag()),
    ]))
    .block(
        Block::bordered()
            .border_style(Style::default().fg(theme::COMMENT))
            .title(Span::styled(" command ", theme::muted())),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
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
        Span::styled(
            "  ? help  ^G run  y yank  ^C cancel  q quit",
            theme::muted(),
        ),
    ]);
    frame.render_widget(Paragraph::new(line).style(theme::bg()), area);
}

fn draw_scan(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([
        Constraint::Length(32),
        Constraint::Length(28),
        Constraint::Min(40),
    ])
    .split(area);

    let mut prof_lines = Vec::new();
    for (i, p) in builtin_profiles().iter().enumerate() {
        let sel = i == app.profile_idx;
        let mark = if sel { "▸ " } else { "  " };
        let style = if sel && app.scan_pane == ScanPane::Profiles {
            theme::selected()
        } else if sel {
            theme::accent()
        } else {
            theme::bg()
        };
        prof_lines.push(Line::from(Span::styled(format!("{mark}{}", p.name), style)));
    }
    let desc = builtin_profiles()[app.profile_idx].description;
    prof_lines.push(Line::from(""));
    prof_lines.push(Line::from(Span::styled(desc, theme::muted())));
    frame.render_widget(
        Paragraph::new(prof_lines).block(pane(" profiles ", app.scan_pane == ScanPane::Profiles)),
        cols[0],
    );

    let dirty = if app.profile_dirty { " (edited)" } else { "" };
    let target_title = format!(" targets{dirty} ");
    let targets = if app.spec.targets.is_empty() {
        Line::from(Span::styled(
            "Enter to set hosts / CIDR / ranges",
            theme::muted(),
        ))
    } else {
        Line::from(Span::styled(&app.spec.targets, theme::ip()))
    };
    frame.render_widget(
        Paragraph::new(vec![
            targets,
            Line::from(""),
            Line::from(Span::styled(
                "space/comma/newline separated",
                theme::muted(),
            )),
            Line::from(Span::styled(
                format!("profile: {}", app.profile_label()),
                theme::script(),
            )),
        ])
        .block(pane(&target_title, app.scan_pane == ScanPane::Targets))
        .wrap(Wrap { trim: false }),
        cols[1],
    );

    draw_options(frame, app, cols[2]);
}

fn draw_options(frame: &mut Frame, app: &App, area: Rect) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let sel = app.option_idx;
    let start = if sel >= inner_h { sel + 1 - inner_h } else { 0 };
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
    let cols = Layout::horizontal([Constraint::Min(50), Constraint::Length(36)]).split(area);
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
                .border_style(Style::default().fg(theme::COMMENT))
                .title(" progress "),
        )
        .gauge_style(Style::default().fg(theme::PINK).bg(theme::CURRENT))
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
            .block(pane(" nmap output ", true))
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
    frame.render_widget(Paragraph::new(hosts).block(pane(" hosts ", false)), cols[1]);
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
        Style::default().fg(theme::FG)
    };
    Line::from(Span::styled(s.to_string(), style))
}

fn draw_results(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([Constraint::Length(34), Constraint::Min(40)]).split(area);
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
    frame.render_widget(
        Paragraph::new(lines).block(pane(&format!(" hosts {}  / filter ", hosts.len()), true)),
        cols[0],
    );

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
            frame.render_widget(
                Paragraph::new(rows)
                    .block(pane(" ports  [ ] pane  o closed  e/m/c export ", false)),
                right[1],
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
                Paragraph::new(lines).block(pane(" scripts ", false)),
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
                Paragraph::new(lines).block(pane(" os / traceroute ", false)),
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
                    .wrap(Wrap { trim: false })
                    .block(pane(" raw xml ", false)),
                right[1],
            );
        }
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
    frame.render_widget(Paragraph::new(lines).block(pane(" history ", true)), area);
}

fn draw_scripts(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([Constraint::Length(22), Constraint::Min(40)]).split(area);
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
        Paragraph::new(cats).block(pane(" category  h/l ", false)),
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
    frame.render_widget(Paragraph::new(lines).block(pane(&title, true)), cols[1]);
}

fn draw_compare(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(30),
        Constraint::Percentage(40),
    ])
    .split(area);
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
    frame.render_widget(Paragraph::new(lines).block(pane(" diff ", false)), cols[2]);
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
    frame.render_widget(
        Paragraph::new(lines).block(pane(title, app.compare_focus == focus)),
        area,
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
                    .border_style(Style::default().fg(theme::PURPLE)),
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
                    .border_style(Style::default().fg(theme::PINK)),
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
    frame.render_widget(
        Paragraph::new(shown)
            .style(theme::bg().fg(theme::YELLOW))
            .block(
                Block::bordered()
                    .title(Span::styled(format!(" {title} "), theme::title()))
                    .border_style(Style::default().fg(theme::CYAN)),
            ),
        popup,
    );
}

fn pane(title: &str, active: bool) -> Block<'_> {
    Block::bordered()
        .title(Span::styled(
            title,
            if active {
                theme::accent()
            } else {
                theme::muted()
            },
        ))
        .border_style(Style::default().fg(if active { theme::PINK } else { theme::COMMENT }))
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
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

const HELP: &str = r#"Nexus-Map — Dracula-themed Nmap frontend

Tabs          1 Scan  2 Live  3 Results  4 History  5 Scripts  6 Compare
Tab/S-Tab     cycle panes          ? this help          q quit

Scan builder
  j/k         move          space/enter toggle or edit
  Enter       set targets   y yank command
  Ctrl-G      run (confirm) extra args are split, never passed to a shell

Live
  j/k scroll log    G follow tail    Ctrl-C SIGINT (then SIGKILL after 3s)

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
  Run `sudo -v` first, or start Nexus-Map via sudo.

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
