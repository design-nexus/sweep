mod app;
#[cfg(test)]
mod audit;
mod aurora;
mod commands;
mod export;
mod fields;
mod input;
mod navigation;
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
    name = "sweep",
    version,
    about = "sweep — Aurora TUI frontend for Nmap",
    after_help = "Pass nmap arguments after -- to load them into the builder:\n  sweep -- nmap -sV scanme.nmap.org"
)]
struct Cli {
    /// Disable terminal mouse capture
    #[arg(long)]
    no_mouse: bool,
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
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
        previous(info);
    }));

    if !cli.no_mouse {
        crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;
    }
    let result = run(&mut terminal, &mut app).await;
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
    ratatui::restore();
    result
}

async fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    let mut events = EventStream::new();
    let mut ticks = tokio::time::interval(Duration::from_millis(200));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let rendered = terminal.draw(|f| ui::draw(f, app))?;
        aurora::paint_wordmark(rendered.buffer)?;
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
                    Some(Ok(Event::Mouse(mouse)))=>app.navigation_mouse(mouse),
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
