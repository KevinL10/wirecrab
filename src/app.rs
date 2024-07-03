use ratatui::widgets::TableState;

use crate::network::sniffer::SnifferPacket;
use std::{error, net::Ipv4Addr};

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
pub struct NetworkEntry {
    pub ip: Ipv4Addr,
    pub host: String,
}

/// Application.
#[derive(Debug)]
pub struct App {
    // TODO: replace String with full data structure (e.g. ip, # packets sent/received)
    pub hosts: Vec<NetworkEntry>,
    pub state: TableState,
    pub running: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            state: TableState::new(),
            hosts: Vec::new(),
        }
    }
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles the tick event of the terminal.
    pub fn tick(&self) {}

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn update(&mut self, data: SnifferPacket) {
        // TODO: check whether src/dst is the user's ip address
        // TODO: add logic to paginate top network requests
        self.hosts.push(NetworkEntry {
            ip: data.src,
            host: data.host,
        });
    }

    pub fn prev_entry(&mut self) {
        let idx = self.state.selected().unwrap_or(0);
        self.state
            .select(if idx > 0 { Some(idx - 1) } else { Some(idx) });
    }

    pub fn next_entry(&mut self) {
        let idx = self.state.selected().unwrap_or(0);
        self.state.select(if idx + 1 < self.hosts.len() {
            Some(idx + 1)
        } else {
            Some(idx)
        });
    }
}
