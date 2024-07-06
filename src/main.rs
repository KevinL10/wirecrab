use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::{io, thread};
use wirecrab::app::{App, AppResult};
use wirecrab::event::{Event, EventHandler};
use wirecrab::handler::handle_key_events;
use wirecrab::network::dns::DnsARecord;
use wirecrab::network::sniffer::{Sniffer, SnifferPacket};
use wirecrab::tui::Tui;

fn main() -> AppResult<()> {
    // Create an application.
    let mut app = App::new();

    // Initialize the terminal user interface.
    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(250);

    // TODO: move into a single Sniffer instance
    let dns = Sniffer::new("en0".into());
    let sniffer = Sniffer::new("en0".into());
    let (tx, rx) = mpsc::channel();
    let (tx_dns, rx_dns) = mpsc::channel();

    let _t = thread::spawn(move || {
        sniffer.start_packet_capture(tx);
    });

    let _t = thread::spawn(move || {
        dns.start_dns_capture(tx_dns);
    });

    // t.join();

    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    // Start the main loop.
    while app.running {
        while let Ok(data) = rx.try_recv() {
            app.update(data);
        }

        while let Ok(data) = rx_dns.try_recv() {
            app.update_dns_cache(data);
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
