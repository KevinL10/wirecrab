use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

mod dns;

const WIFI_DEVICE: &str = "en0";

// https://en.wikipedia.org/wiki/Ethernet_frame
struct EthernetFrame<'a> {
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: [u8; 2],
    payload: &'a [u8],
}

// IPv4: https://datatracker.ietf.org/doc/html/rfc791#section-3.1
// IPv6: https://datatracker.ietf.org/doc/html/rfc2460
// TODO: add support for IPv6 headers
#[derive(Debug)]
struct IPv4Packet<'a> {
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
    protocol: u8, // 8 bits

    /* A checksum on the header only.  The checksum field is the 16 bit one's complement of the one's
     complement sum of all 16 bit words in the header.
    */
    checksum: u16, // 16 bits

    /* Source IP address */
    src: Ipv4Addr, // 32 bits

    /*  Destination IP address */
    dst: Ipv4Addr, // 32 bits

    options: Option<&'a [u8]>, // variable bits, given by IHL

    payload: &'a [u8],
}

fn parse_ethernet_frame(data: &[u8]) -> EthernetFrame {
    let dst: [u8; 6] = data[..6].try_into().expect("error parsing ethernet dst");
    let src: [u8; 6] = data[6..12].try_into().expect("error parsing ethernet src");
    let ethertype: [u8; 2] = data[12..14]
        .try_into()
        .expect("error parsing ethernet ethertype");
    let payload: &[u8] = data[14..]
        .try_into()
        .expect("error parsing ethernet payload");

    EthernetFrame {
        dst,
        src,
        ethertype,
        payload,
    }
}

fn parse_ipv4_packet(data: &[u8]) -> IPv4Packet {
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

    IPv4Packet {
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

fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<String>()
}

// Returns the domain name for the IP if one exists; otherwise return the ip back as a String
fn translate_ip(ip: Ipv4Addr) -> String {
    dns::reverse_lookup(ip).unwrap_or(ip.to_string())
}

fn main() {
    let devices = pcap::Device::list().expect("devices lookup failed");

    // get the wifi device
    let device = devices
        .into_iter()
        .find(|d| d.name == WIFI_DEVICE)
        .expect("could not get wifi device");

    let mut cap = pcap::Capture::from_device(device)
        .expect("failed to get capture")
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter("src port 80 or src port 443", true).unwrap();
    // cap.filter("host www.testingmcafeesites.com", true).unwrap();

    // let mut count = 0;
    cap.for_each(None, |packet| {
        let frame = parse_ethernet_frame(packet.data);
        let packet = parse_ipv4_packet(frame.payload);

        println!(
            "connection from {:?} to {:?} on protocol {:?}",
            translate_ip(packet.src),
            translate_ip(packet.dst),
            packet.protocol
        );
    })
    .unwrap();
}
