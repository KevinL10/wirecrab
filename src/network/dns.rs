use std::net::{IpAddr, Ipv4Addr};
use std::vec;

use std::net::UdpSocket;

// Google's DNS server
// TODO: replace with local DNS server
const DNS_SERVER: &str = "8.8.8.8:53";
// const DNS_SERVER: &str = "192.168.2.1:53";

// https://www.ietf.org/rfc/rfc1035.txt - section 4.1
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

fn parse_dns_response(response: &[u8]) -> Option<String> {
    if response.len() < 12 {
        return None;
    }

    let ancount = ((response[6] as u16) << 8) | response[7] as u16;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;

    // Skip the question section
    while response[pos] != 0 {
        pos += response[pos] as usize + 1;
    }
    pos += 5;

    // Process the answer section
    for _ in 0..ancount {
        // Skip the name field (could be a pointer)
        if response[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while response[pos] != 0 {
                pos += response[pos] as usize + 1;
            }
            pos += 1;
        }

        // Check the type field (should be PTR)
        let qtype = ((response[pos] as u16) << 8) | response[pos + 1] as u16;
        if qtype != 0x000C {
            return None;
        }
        pos += 2;

        // Skip QCLASS, TTL, and RDLENGTH fields
        pos += 8;

        // Read the PTR record
        let rdlength = ((response[pos - 2] as u16) << 8) | response[pos - 1] as u16;
        let end = pos + rdlength as usize;

        let mut ptr_name = String::new();
        while pos < end {
            let len = response[pos] as usize;
            if len == 0 {
                break;
            }
            if !ptr_name.is_empty() {
                ptr_name.push('.');
            }
            ptr_name.push_str(&String::from_utf8_lossy(&response[pos + 1..pos + 1 + len]));
            pos += len + 1;
        }

        return Some(ptr_name);
    }

    None
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
