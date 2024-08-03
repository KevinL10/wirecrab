use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::{io, thread};
use wirecrab::app::{App, AppResult};
use wirecrab::event::{Event, EventHandler};
use wirecrab::handler::handle_key_events;
use wirecrab::network::sniffer::{Sniffer, SnifferPacket};
use wirecrab::tui::Tui;

fn main() -> AppResult<()> {
    let args = env::args().collect::<Vec<_>>();
    let debug = args.iter().any(|arg| arg == "--debug");

    let mut app = App::new();

    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(250);

    // TODO: move into a single Sniffer instance
    // TODO: sniff across all network devices
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

    let mut tui = Tui::new(terminal, events);
    if !debug {
        tui.init()?;
    }

    while app.running {
        while let Ok(data) = rx.try_recv() {
            app.handle_packet(data);
        }

        while let Ok(data) = rx_dns.try_recv() {
            app.handle_dns_message(data);
        }

        if !debug {
            tui.draw(&mut app)?;
        }

        match tui.events.next()? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => handle_key_events(key_event, &mut app)?,
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
        }
    }

    tui.exit()?;
    Ok(())
}
