mod tui;

use std::io;
use std::panic;

fn main() -> io::Result<()> {
    // Install panic hook that restores the terminal before printing the panic.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = ratatui::restore();
        default_hook(info);
    }));

    let mut terminal = ratatui::init();
    let result = tui::run(&mut terminal);
    ratatui::restore();
    result
}
