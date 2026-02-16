pub mod app;
pub mod handler;
pub mod ui;

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event};
use ratatui::DefaultTerminal;

use app::App;

const TICK_RATE: Duration = Duration::from_millis(50);

pub fn run(terminal: &mut DefaultTerminal) -> io::Result<()> {
    let mut app = App::new();

    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(TICK_RATE)? {
            if let Event::Key(key) = event::read()? {
                // Ignore key release events on Windows (crossterm quirk)
                if key.kind == crossterm::event::KeyEventKind::Press {
                    handler::handle_key(&mut app, key);
                }
            }
        }

        app.process_events();
    }

    Ok(())
}
