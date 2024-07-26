use ratatui::widgets::TableState;

use crate::network::{
    dns::{DNSRData, DnsDirectRecord, DnsMessage, DnsResourceRecord},
    ip,
    sniffer::SnifferPacket,
};
use std::{collections::HashMap, error, fs::File, io::Write, net::IpAddr};

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

    // Mapping between ip address and hostname from live DNS traffic
    pub dns_cache: HashMap<IpAddr, String>,

    // Inverse mapping between a domain and its resolved CNAME. For example, if www.google.com
    // returns a CNAME record for www.l.google.com, we store the mapping {"www.l.google.com": "www.google.com"}
    // We use this map to recursively resolve any CNAMEs to the original name
    pub inv_cname_map: HashMap<String, String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            state: TableState::new(),
            hosts: Vec::new(),
            entries: HashMap::new(),
            dns_cache: HashMap::new(),
            inv_cname_map: HashMap::new(),
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

    /// NOTE: we need to be careful about the order in which we handle DNS vs query messages. Even
    /// though the DNS query will precede the actual request, we may process the DNS query only after
    /// we've already updated the entry.
    ///
    /// To address this, we insert the ip->host mapping into both the DNS cache which the update_entries reads from,
    /// and also retroactively update the entries table once we receive more information about that ip address
    ///
    /// We assume that we process all CNAME resolution queries before the terminal query. In other words,
    /// when we process the terminal query, we will already have a graph mapping from all resolved CNAMES
    /// to the original query domain. *NOTE*: this assumption may not be valid.
    pub fn handle_dns_message(&mut self, data: DnsMessage) {
        for resource in data.answers {
            // println!("{:?} {:?}", resource.rdata, resource.name);
            match resource.rdata {
                DNSRData::CNAME(cname) => {
                    self.inv_cname_map.insert(cname, resource.name);
                }
                DNSRData::A(ipv4) => {
                    self.dns_cache
                        .insert(IpAddr::V4(ipv4), resource.name.clone());
                    self.update_entry(IpAddr::V4(ipv4), resource.name);
                }
                DNSRData::AAAA(ipv6) => {
                    self.dns_cache
                        .insert(IpAddr::V6(ipv6), resource.name.clone());
                    self.update_entry(IpAddr::V6(ipv6), resource.name);
                }
                _ => (),
            };
        }
    }

    /// Update self.entries with the new resource name
    pub fn update_entry(&mut self, ip: IpAddr, host: String) {
        if !self.entries.contains_key(&ip) {
            return;
        }

        self.entries.entry(ip).and_modify(|entry| entry.host = host);
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
                host: if self.dns_cache.contains_key(&data.src) {
                    self.dns_cache[&data.src].clone()
                } else {
                    let host = ip::translate_ip(data.src);
                    self.dns_cache.insert(data.src, host.clone());
                    host
                },
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

    pub fn clear(&mut self) {
        self.entries.clear();
        self.dns_cache.clear();
        self.inv_cname_map.clear();
        self.hosts.clear();
    }
}
