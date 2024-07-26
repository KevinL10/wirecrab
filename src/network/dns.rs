use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::vec;

use std::net::UdpSocket;

// Google's DNS server
// TODO: replace with local DNS server
// const DNS_SERVER: &str = "8.8.8.8:53";
const DNS_SERVER: &str = "64.71.255.204:53";

#[derive(Debug)]
pub struct DnsDirectRecord {
    pub domain: String,
    pub records: Vec<IpAddr>,
}
#[derive(Debug)]
pub struct DnsHeader {
    id: u16,           // 16 bits
    flags: u16,        // 16 bits
    pub qd_count: u16, // 16 bits
    pub an_count: u16, // 16 bits
    pub ns_count: u16, // 16 bits
    pub ar_count: u16, // 16 bits
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String, // variable length
    pub qtype: u16,    // 16 bits
    pub qclass: u16,   // 16 bits
}

// https://www.ietf.org/rfc/rfc1035.txt - section 4.1
#[derive(Debug)]
pub struct DnsMessage {
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    authorities: Vec<DnsResourceRecord>,
    additional: Vec<DnsResourceRecord>,
}

#[derive(Debug)]
pub enum DNSRData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    PTR(String),
    UNIMPLEMENTED(),
}

#[derive(Debug)]
pub struct DnsResourceRecord {
    name: String,  // variable length
    rtype: u16,    // 16 bits
    rclass: u16,   // 16 bits
    ttl: u32,      // 32 bits
    rdlength: u16, // 16 bits
    rdata: DNSRData,
}

impl DnsResourceRecord {
    fn parse(message: &[u8], index: &mut usize) -> DnsResourceRecord {
        let name = parse_name(message, index);

        let rtype = u16::from_be_bytes([message[*index], message[*index + 1]]);
        let rclass = u16::from_be_bytes([message[*index + 2], message[*index + 3]]);
        let ttl = u32::from_be_bytes([
            message[*index + 4],
            message[*index + 5],
            message[*index + 6],
            message[*index + 7],
        ]);
        let rdlength = u16::from_be_bytes([message[*index + 8], message[*index + 9]]);
        *index += 10;

        let rdata_end = *index + rdlength as usize;
        let rdata = DnsResourceRecord::parse_r_data(rtype, message, index);

        *index = rdata_end;

        DnsResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
        }
    }

    pub fn parse_r_data(rtype: u16, message: &[u8], index: &mut usize) -> DNSRData {
        if rtype == 1 {
            return DNSRData::A(Ipv4Addr::new(
                message[*index + 0],
                message[*index + 1],
                message[*index + 2],
                message[*index + 3],
            ));
        } else if rtype == 28 {
            return DNSRData::AAAA(Ipv6Addr::new(
                u16::from_be_bytes([message[*index + 0], message[*index + 1]]),
                u16::from_be_bytes([message[*index + 2], message[*index + 3]]),
                u16::from_be_bytes([message[*index + 4], message[*index + 5]]),
                u16::from_be_bytes([message[*index + 6], message[*index + 7]]),
                u16::from_be_bytes([message[*index + 8], message[*index + 9]]),
                u16::from_be_bytes([message[*index + 10], message[*index + 11]]),
                u16::from_be_bytes([message[*index + 12], message[*index + 13]]),
                u16::from_be_bytes([message[*index + 14], message[*index + 15]]),
            ));
        } else if rtype == 5 {
            return DNSRData::CNAME(parse_name(message, index));
        } else if rtype == 12 {
            return DNSRData::PTR(parse_name(message, index));
        }
        return DNSRData::UNIMPLEMENTED();
    }
}

impl DnsMessage {
    pub fn parse(message: &[u8]) -> DnsMessage {
        let mut index = 0;
        let header = DnsHeader::parse(message, &mut index);

        let questions: Vec<DnsQuestion> = (0..header.qd_count)
            .map(|_| DnsQuestion::parse(message, &mut index))
            .collect();
        let answers: Vec<DnsResourceRecord> = (0..header.an_count)
            .map(|_| DnsResourceRecord::parse(message, &mut index))
            .collect();
        let authorities: Vec<DnsResourceRecord> = (0..header.ns_count)
            .map(|_| DnsResourceRecord::parse(message, &mut index))
            .collect();
        let additional: Vec<DnsResourceRecord> = (0..header.ar_count)
            .map(|_| DnsResourceRecord::parse(message, &mut index))
            .collect();

        DnsMessage {
            questions,
            answers,
            authorities,
            additional,
        }
    }
}

impl DnsHeader {
    fn parse(message: &[u8], index: &mut usize) -> DnsHeader {
        let id = ((message[0] as u16) << 8) | (message[1] as u16);
        let flags = ((message[2] as u16) << 8) | (message[3] as u16);
        let qd_count = ((message[4] as u16) << 8) | (message[5] as u16);
        let an_count = ((message[6] as u16) << 8) | (message[7] as u16);
        let ns_count = ((message[8] as u16) << 8) | (message[9] as u16);
        let ar_count = ((message[10] as u16) << 8) | (message[11] as u16);

        *index = 12;

        DnsHeader {
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        }
    }
}

impl DnsQuestion {
    pub fn parse(message: &[u8], index: &mut usize) -> DnsQuestion {
        let qname = parse_name(message, index);
        let qtype = ((message[*index] as u16) << 8) | (message[*index + 1] as u16);
        let qclass = ((message[*index + 2] as u16) << 8) | (message[*index + 3] as u16);
        *index += 4;

        DnsQuestion {
            qname,
            qtype,
            qclass,
        }
    }
}

fn parse_dns_response(response: &[u8]) -> Option<String> {
    let message = DnsMessage::parse(response);
    if message.answers.len() == 0 {
        return None;
    }

    if let DNSRData::PTR(ptr) = &message.answers[0].rdata {
        return Some(ptr.to_string());
    }

    return None;
}

// TODO: replace index with cursor
fn parse_name(packet: &[u8], index: &mut usize) -> String {
    let mut name = String::new();
    while packet[*index] != 0 {
        if packet[*index] & 0xC0 == 0xC0 {
            // Name compression
            let offset = ((packet[*index] as usize & 0x3F) << 8) | packet[*index + 1] as usize;
            *index += 2;
            if let Some(compressed_name) = parse_compressed_name(packet, offset) {
                name.push_str(&compressed_name);
            }
            return name;
        } else {
            let length = packet[*index] as usize;
            *index += 1;
            if *index + length > packet.len() {
                panic!("exceeded length")
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&packet[*index..*index + length]));
            *index += length;
        }
    }
    *index += 1;
    name
}

fn parse_compressed_name(packet: &[u8], mut index: usize) -> Option<String> {
    let mut name = String::new();
    while packet[index] != 0 {
        if packet[index] & 0xC0 == 0xC0 {
            let offset = ((packet[index] as usize & 0x3F) << 8) | packet[index + 1] as usize;
            index = offset;
        } else {
            let length = packet[index] as usize;
            index += 1;
            if index + length > packet.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&packet[index..index + length]));
            index += length;
        }
    }
    Some(name)
}

fn build_reverse_packet(addr: IpAddr) -> Vec<u8> {
    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    #[rustfmt::skip]
    let mut packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Standard Query with RA (Recursion Available) flag set
        0x00, 0x01, // Question count = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];

    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    let mut parts = Vec::new();
    if let IpAddr::V4(addr) = addr {
        for octet in addr.octets().iter().rev() {
            parts.push(octet.to_string());
        }
    } else if let IpAddr::V6(addr) = addr {
        for segment in addr.segments().iter().rev() {
            parts.push(format!("{:x}", segment & 0x000F));
            parts.push(format!("{:x}", (segment & 0x00F0) >> 4));
            parts.push(format!("{:x}", (segment & 0x0F00) >> 8));
            parts.push(format!("{:x}", (segment & 0xF000) >> 12));
        }
    }

    for part in parts {
        packet.push(part.len() as u8);
        packet.extend(part.as_bytes());
    }

    // ipv4 should query `in-addr.arpa`
    if addr.is_ipv4() {
        packet.extend(vec![
            0x07, b'i', b'n', b'-', b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a',
        ]);
    }

    // ipv6 should query `ip6.arpa`
    if addr.is_ipv6() {
        packet.extend(vec![0x03, b'i', b'p', b'6', 0x04, b'a', b'r', b'p', b'a']);
    }

    #[rustfmt::skip]
    packet.extend(vec![
        0x00, // null terminator for QNAME
        0x00, 0x0C, // QTYPE: PTR
        0x00, 0x01, // QCLASS: IN
    ]);

    packet
}

/* Returns the domain name pointed to by addr in the PTR record */
pub fn reverse_lookup(addr: IpAddr) -> Option<String> {
    let query_packet = build_reverse_packet(addr);

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Unable to bind to local socket");
    socket
        .connect(DNS_SERVER)
        .expect("Unable to connect to DNS server");
    socket
        .send(&query_packet)
        .expect("Unable to send DNS query");

    let mut response_packet = [0u8; 512];
    let size = socket
        .recv(&mut response_packet)
        .expect("Unable to receive DNS response");

    parse_dns_response(&response_packet[..size])
}
