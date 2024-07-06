use crate::network::dns;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// IPv6: https://datatracker.ietf.org/doc/html/rfc2460
pub struct Ipv6Packet<'a> {
    version: u8, // 4 bits

    traffic_class: u8, // 8 bits

    flow_label: u32, // 20 bits

    payload_length: u16, // 16 bits

    next_header: u8, // 8 bits

    hop_limit: u8, // 8 bits

    pub src: Ipv6Addr, // 128 bits

    pub dst: Ipv6Addr, // 128 bits

    payload: &'a [u8],
}

// IPv4: https://datatracker.ietf.org/doc/html/rfc791#section-3.1
#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    /* The Version field indicates the format of the internet header */
    version: u8, // 4 bits

    /* Internet Header Length is the length of the internet header in 32 bit words, and thus points to the beginning of the data.  */
    ihl: u8, // 4 bits

    /* The Type of Service provides an indication of the abstract parameters of the quality of service desired.
    Bits 0-2:  Precedence.
    Bit    3:  0 = Normal Delay,      1 = Low Delay.
    Bits   4:  0 = Normal Throughput, 1 = High Throughput.
    Bits   5:  0 = Normal Relibility, 1 = High Relibility.
    Bit  6-7:  Reserved for Future Use.
    */
    service_type: u8, // 8 bits

    /* Total Length is the length of the datagram, measured in octets,
    including internet header and data.
     */
    length: u16, // 16 bits

    /* An identifying value assigned by the sender to aid in assembling the
    fragments of a datagram.
     */
    identification: u16, // 16 bits

    /* Various Control Flags.

     Bit 0: reserved, must be zero
     Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
     Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
    */
    flags: u8, // 3 bits

    /* This field indicates where in the datagram this fragment belongs.  */
    fragment_offset: u16, // 13 bits

    /* This field indicates the maximum time the datagram is allowed to
    remain in the internet system. */
    ttl: u8, // 8 bits

    /* This field indicates the next level protocol used in the data
    portion of the internet datagram.

    Specified in https://datatracker.ietf.org/doc/html/rfc790 */
    pub protocol: u8, // 8 bits

    /* A checksum on the header only.  The checksum field is the 16 bit one's complement of the one's
     complement sum of all 16 bit words in the header.
    */
    checksum: u16, // 16 bits

    /* Source IP address */
    pub src: Ipv4Addr, // 32 bits

    /*  Destination IP address */
    pub dst: Ipv4Addr, // 32 bits

    options: Option<&'a [u8]>, // variable bits, given by IHL

    payload: &'a [u8],
}

// TODO: properly handle next_header
pub fn parse_ipv6_packet(data: &[u8]) -> Ipv6Packet {
    let version = (data[0] >> 4) & 0x0F;
    let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
    let flow_label = ((data[1] as u32 & 0x0F) << 16) | (data[2] as u32) << 8 | (data[3] as u32);
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let src = Ipv6Addr::new(
        u16::from_be_bytes([data[8], data[9]]),
        u16::from_be_bytes([data[10], data[11]]),
        u16::from_be_bytes([data[12], data[13]]),
        u16::from_be_bytes([data[14], data[15]]),
        u16::from_be_bytes([data[16], data[17]]),
        u16::from_be_bytes([data[18], data[19]]),
        u16::from_be_bytes([data[20], data[21]]),
        u16::from_be_bytes([data[22], data[23]]),
    );

    let dst = Ipv6Addr::new(
        u16::from_be_bytes([data[24], data[25]]),
        u16::from_be_bytes([data[26], data[27]]),
        u16::from_be_bytes([data[28], data[29]]),
        u16::from_be_bytes([data[30], data[31]]),
        u16::from_be_bytes([data[32], data[33]]),
        u16::from_be_bytes([data[34], data[35]]),
        u16::from_be_bytes([data[36], data[37]]),
        u16::from_be_bytes([data[38], data[39]]),
    );

    let payload = &data[40..];

    Ipv6Packet {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        src,
        dst,
        payload,
    }
}

pub fn parse_ipv4_packet(data: &[u8]) -> Ipv4Packet {
    let version = data[0] >> 0x4;
    let ihl = data[0] & 0x0F;
    let ihl_in_bytes = (ihl * 4) as usize;

    let service_type = data[1];

    let length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);

    let flags = data[6] >> 0x5;
    let fragment_offset = u16::from_be_bytes([data[6] & 0b111, data[7]]);

    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);

    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let options = if ihl_in_bytes > 20 {
        Some(&data[20..ihl_in_bytes])
    } else {
        None
    };

    let payload = &data[ihl_in_bytes..];

    Ipv4Packet {
        version,
        ihl,
        service_type,
        length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src,
        dst,
        options,
        payload,
    }
}

// Returns the domain name for the IP if one exists; otherwise return the ip back as a String
pub fn translate_ip(ip: IpAddr) -> String {
    dns::reverse_lookup(ip).unwrap_or(ip.to_string())
}
