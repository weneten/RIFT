//! The terminal UI: `rift` without arguments (or `rift tui`) on a terminal. It runs in the
//! RIFT container like every other command (`docker exec -it`), talks to the daemon over the
//! same admin socket as the CLI and offers what the CLI and the web panel offer, by keyboard
//! and mouse. `RIFT_TUI=false` turns it off; the CLI is unaffected either way.

mod app;
mod form;
mod theme;
mod ui;

use crate::config::Config;
use anyhow::{ensure, Result};
use app::{App, Msg};
use ratatui::crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    },
    execute,
};
use std::{io::IsTerminal, path::PathBuf, time::Duration};

/// Whether `rift` without a command should open the UI here: it is on and both ends are a
/// terminal.
pub fn wanted(config: &Config) -> bool {
    config.tui && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub async fn run(config: Config, config_path: PathBuf) -> Result<()> {
    ensure!(
        config.tui,
        "the terminal UI is off (RIFT_TUI=false in .env); turn it on there and recreate the container (docker compose up -d --force-recreate), or use the rift commands"
    );
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "the terminal UI needs a terminal. Typed on a terminal, through the host command rift? Then that command is older than this image: run sudo sh deploy/install-cli in the RIFT directory. Directly through Docker, use docker exec -it"
    );
    let mut terminal = ratatui::try_init()?;
    // ratatui's panic hook restores the screen; mouse reporting has to go first.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(
            std::io::stdout(),
            DisableMouseCapture,
            DisableBracketedPaste
        );
        hook(info);
    }));
    execute!(std::io::stdout(), EnableMouseCapture, EnableBracketedPaste)?;
    let result = run_loop(&mut terminal, config, config_path).await;
    let _ = execute!(
        std::io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste
    );
    ratatui::restore();
    result
}

async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    config: Config,
    config_path: PathBuf,
) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // Terminal input is read on a thread of its own; reading blocks.
    let input = tx.clone();
    std::thread::spawn(move || {
        while let Ok(event) = event::read() {
            if input.send(Msg::Event(event)).is_err() {
                break;
            }
        }
    });
    let mut app = App::new(config, config_path, tx);
    app.spawn_fetch();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        terminal.draw(|frame| ui::draw(frame, &mut app))?;
        tokio::select! {
            Some(msg) = rx.recv() => {
                app.on_msg(msg);
                // Handle whatever else is queued (fast typing, wheel bursts) before drawing.
                while let Ok(msg) = rx.try_recv() {
                    app.on_msg(msg);
                    if app.quit { break; }
                }
            }
            _ = tick.tick() => app.on_tick(),
        }
        if app.quit {
            return Ok(());
        }
    }
}
