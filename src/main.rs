use network::sniffer::start_packet_capture;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::sync::mpsc;
use std::{io, thread};
use wirecrab::app::{App, AppResult};
use wirecrab::event::{Event, EventHandler};
use wirecrab::handler::handle_key_events;
use wirecrab::tui::Tui;

mod network;

fn main() -> AppResult<()> {
    // Create an application.
    let mut app = App::new();

    // Initialize the terminal user interface.
    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(250);
    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        start_packet_capture(tx);
    });

    // Start the main loop.
    while app.running {
        while let Ok(data) = rx.try_recv() {
            app.update(data);
        }

        // Render the user interface.
        tui.draw(&mut app)?;
        // Handle events.
        match tui.events.next()? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => handle_key_events(key_event, &mut app)?,
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
        }
    }

    // Exit the user interface.
    tui.exit()?;
    Ok(())
}
