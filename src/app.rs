use ratatui::widgets::TableState;

use crate::network::sniffer::SnifferPacket;
use std::{
    collections::HashMap,
    error,
    net::{IpAddr, Ipv4Addr},
};

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
pub struct NetworkEntry {
    pub ip: IpAddr,
    pub host: String,
    pub num_packets: u32,
}

/// Application.
#[derive(Debug)]
pub struct App {
    // Mainain map insert order with a separate hosts vector
    pub hosts: Vec<IpAddr>,
    pub state: TableState,

    pub entries: HashMap<IpAddr, NetworkEntry>,
    pub running: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            state: TableState::new(),
            hosts: Vec::new(),
            entries: HashMap::new(),
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
        if !self.entries.contains_key(&data.src) {
            self.hosts.push(data.src);
        }

        self.entries
            .entry(data.src)
            .and_modify(|e| (*e).num_packets += 1)
            .or_insert(NetworkEntry {
                ip: data.src,
                host: data.host,
                num_packets: 1,
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
