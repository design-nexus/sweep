mod app;
mod export;
mod fields;
mod input;
mod nmap;
mod persist;
mod theme;
mod ui;

use crate::app::App;
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "nexus-map",
    about = "Nexus-Map — Dracula-themed TUI frontend for Nmap",
    after_help = "Pass nmap arguments after -- to load them into the builder:\n  nexus-map -- nmap -sV scanme.nmap.org"
)]
struct Cli {
    /// Open an nmap XML file
    xml: Option<PathBuf>,
    /// Target host, CIDR, or range
    #[arg(short, long)]
    target: Option<String>,
    /// Zenmap-style profile name (e.g. "Quick scan")
    #[arg(short, long)]
    profile: Option<String>,
    /// Remaining args treated as an nmap command line
    #[arg(last = true)]
    nmap: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut app = App::new()?;
    app.apply_cli(cli.target, cli.profile, cli.xml, cli.nmap)?;

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app).await;
    ratatui::restore();
    result
}

async fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    let mut events = EventStream::new();
    let mut ticks = tokio::time::interval(Duration::from_millis(200));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        if app.should_quit {
            break;
        }
        tokio::select! {
            _ = ticks.tick() => {
                app.on_tick().await;
            }
            maybe = events.next() => {
                match maybe {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        app.handle_key(key);
                    }
                    Some(Ok(Event::Resize(_, _))) => {}
                    Some(Err(e)) => anyhow::bail!(e),
                    None => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
