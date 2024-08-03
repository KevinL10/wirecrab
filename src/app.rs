use ratatui::widgets::TableState;

use crate::network::{
    dns::{reverse_lookup, DNSRData, DnsDirectRecord, DnsMessage, DnsResourceRecord},
    ip,
    sniffer::SnifferPacket,
};
use std::{collections::HashMap, error, fs::File, hash::Hash, io::Write, net::IpAddr, slice::Iter};

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
pub struct HostInfo {
    // pub ip: IpAddr,
    // pub host: String,
    pub num_packets: u32,
}

#[derive(Debug)]
pub struct NetworkEntry<'a> {
    pub ip: &'a IpAddr,
    pub domain: Option<&'a String>,
    pub info: &'a HostInfo,
}

/// Application.
#[derive(Debug)]
pub struct App {
    pub state: TableState,

    // Mapping between ip address and hostname from live DNS traffic
    pub ip_to_domain: HashMap<IpAddr, String>,

    // Mapping between ip address and hostname from reverse lookups (PTR records)
    pub ip_to_domain_fallback: HashMap<IpAddr, String>,

    // Mainain map insert order with a separate hosts vector
    // TODO: abstract into a separate HashMap class
    pub host_ips: Vec<IpAddr>,

    // Inverse mapping between a domain and its resolved CNAME. For example, if www.google.com
    // returns a CNAME record for www.l.google.com, we store the mapping {"www.l.google.com": "www.google.com"}
    // If multiple records point to the same CNAME, we store the most recent resolution.
    pub inv_cname_map: HashMap<String, String>,

    pub host_info: HashMap<IpAddr, HostInfo>,
    pub running: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            state: TableState::new(),
            host_ips: Vec::new(),
            inv_cname_map: HashMap::new(),
            ip_to_domain: HashMap::new(),
            ip_to_domain_fallback: HashMap::new(),
            host_info: HashMap::new(),
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

    /// We assume that we process all CNAME resolution queries before the terminal query. In other words,
    /// when we process the terminal query, we will already have a graph mapping from all resolved CNAMES
    /// to the original query domain. *NOTE*: this assumption may not be valid.
    pub fn handle_dns_message(&mut self, data: DnsMessage) {
        for resource in data.answers {
            match resource.rdata {
                DNSRData::CNAME(cname) => {
                    self.inv_cname_map.insert(cname, resource.name);
                }
                DNSRData::A(ipv4) => {
                    self.update_ip_domain_mapping(IpAddr::V4(ipv4), resource.name);
                }
                DNSRData::AAAA(ipv6) => {
                    self.update_ip_domain_mapping(IpAddr::V6(ipv6), resource.name);
                }
                _ => (),
            };
        }
    }

    /// Updates the ip-domain mapping so that the ip points to the domain after
    /// handling any CNAME resolutions.
    pub fn update_ip_domain_mapping(&mut self, ip: IpAddr, domain: String) {
        let mut domain = domain;
        while let Some(original_domain) = self.inv_cname_map.get(&domain) {
            domain = original_domain.to_string();
        }

        self.ip_to_domain.insert(ip, domain);
    }

    pub fn handle_packet(&mut self, data: SnifferPacket) {
        if !self.host_info.contains_key(&data.src) {
            self.host_ips.push(data.src);

            // Look up PTR record to resolve domain name
            if let Some(domain) = reverse_lookup(data.src) {
                self.ip_to_domain_fallback
                    .insert(data.src, format!("!!: {}", domain));
            }
        }

        self.host_info
            .entry(data.src)
            .and_modify(|e| (*e).num_packets += 1)
            .or_insert(HostInfo { num_packets: 1 });
    }

    /// Returns a list of network entries to render, ordered by insertion time
    pub fn entries_to_render(&self) -> impl Iterator<Item = NetworkEntry> {
        self.host_ips.iter().map(|ip| {
            let info = self
                .host_info
                .get(ip)
                .expect(format!("missing ip {} in host info", ip).as_str());

            NetworkEntry {
                ip,
                domain: self
                    .ip_to_domain
                    .get(ip)
                    .or(self.ip_to_domain_fallback.get(ip)),
                info: info,
            }
        })
    }

    pub fn prev_entry(&mut self) {
        let idx = self.state.selected().unwrap_or(0);
        self.state
            .select(if idx > 0 { Some(idx - 1) } else { Some(idx) });
    }

    pub fn next_entry(&mut self) {
        let idx = self.state.selected().unwrap_or(0);
        self.state.select(if idx + 1 < self.host_ips.len() {
            Some(idx + 1)
        } else {
            Some(idx)
        });
    }

    pub fn clear(&mut self) {
        self.inv_cname_map.clear();
        self.host_ips.clear();
        self.host_info.clear();
        self.ip_to_domain.clear();
        self.ip_to_domain_fallback.clear();
    }
}
