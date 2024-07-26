use crate::app::{App, AppResult};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub fn handle_key_events(key_event: KeyEvent, app: &mut App) -> AppResult<()> {
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.quit();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.prev_entry();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.next_entry();
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.quit();
            } else {
                app.clear();
            }
        }
        _ => {}
    }
    Ok(())
}
