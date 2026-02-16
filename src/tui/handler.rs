use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{App, SpooferState, Tab};

pub fn handle_key(app: &mut App, key: KeyEvent) {
    // Global keys
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.spoofer_state == SpooferState::Running {
                app.stop_spoofer();
            } else {
                app.running = false;
            }
            return;
        }
        KeyCode::Char('q') => {
            if app.spoofer_state == SpooferState::Running {
                app.stop_spoofer();
            } else {
                app.running = false;
            }
            return;
        }
        KeyCode::Tab => {
            app.tab = app.tab.next();
            return;
        }
        KeyCode::BackTab => {
            app.tab = app.tab.prev();
            return;
        }
        _ => {}
    }

    // Per-tab keys
    match app.tab {
        Tab::Interfaces => handle_interfaces(app, key),
        Tab::Scanner => handle_scanner(app, key),
        Tab::Spoofer => handle_spoofer(app, key),
    }
}

fn handle_interfaces(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up => {
            if app.iface_index > 0 {
                app.iface_index -= 1;
            }
        }
        KeyCode::Down => {
            if app.iface_index + 1 < app.interfaces.len() {
                app.iface_index += 1;
            }
        }
        KeyCode::Enter => {
            app.select_interface();
        }
        _ => {}
    }
}

fn handle_scanner(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up => {
            if app.scan_index > 0 {
                app.scan_index -= 1;
            }
        }
        KeyCode::Down => {
            if app.scan_index + 1 < app.scan_results.len() {
                app.scan_index += 1;
            }
        }
        KeyCode::Enter => {
            app.start_scan();
        }
        KeyCode::Char('g') => {
            app.set_gateway_from_scan();
        }
        KeyCode::Char('t') => {
            app.set_target_from_scan();
        }
        _ => {}
    }
}

fn handle_spoofer(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            if app.spoofer_state == SpooferState::Idle {
                app.start_spoofer();
            }
        }
        KeyCode::Esc => {
            app.stop_spoofer();
        }
        KeyCode::Char('f') => {
            if app.spoofer_state == SpooferState::Idle {
                app.toggle_forward();
            }
        }
        KeyCode::Char('c') => {
            if app.spoofer_state == SpooferState::Idle {
                app.clear_target();
            }
        }
        _ => {}
    }
}
