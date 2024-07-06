use std::net::IpAddr;
use std::sync::mpsc::Sender;

use pcap::Device;

use crate::network::dns;
use crate::network::ethernet;
use crate::network::ip;
use crate::network::udp;

use super::dns::DnsARecord;

pub struct SnifferPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub host: String,
}

pub struct Sniffer {
    device: Device,
}

impl Sniffer {
    pub fn new(device_name: String) -> Self {
        let devices = pcap::Device::list().expect("devices lookup failed");

        // get the wifi device
        let device = devices
            .into_iter()
            .find(|d| d.name == device_name)
            .expect("could not get wifi device");

        Self { device }
    }

    pub fn start_dns_capture(&self, tx: Sender<DnsARecord>) {
        let mut cap = pcap::Capture::from_device(self.device.clone())
            .expect("failed to get capture")
            .immediate_mode(true)
            .open()
            .unwrap();

        // filter DNS responses
        cap.filter("udp src port 53", true).unwrap();

        cap.for_each(None, |packet| {
            let frame = ethernet::parse_ethernet_frame(packet.data);

            if frame.ethertype[0] == 0x08 && frame.ethertype[1] == 0x00 {
                let packet = ip::parse_ipv4_packet(frame.payload);
                let datagram = udp::parse_udp_packet(packet.payload);
                let record = dns::parse_dns_a_response(datagram.data);

                if let Some(record) = record {
                    tx.send(record).unwrap();
                }
            } else if frame.ethertype[0] == 0x86 && frame.ethertype[1] == 0xdd {
                let packet = ip::parse_ipv6_packet(frame.payload);
                // tx.send(SnifferPacket {
                //     src: IpAddr::V6(packet.src),
                //     dst: IpAddr::V6(packet.dst),
                //     host: ip::translate_ip(IpAddr::V6(packet.src)),
                // })
                // .expect("sniffer: failed to send ipv6 packet");
            } else {
                panic!("unsupported ethertype {:?}", frame.ethertype);
            }
        })
        .unwrap();
    }

    pub fn start_packet_capture(&self, tx: Sender<SnifferPacket>) {
        let mut cap = pcap::Capture::from_device(self.device.clone())
            .expect("failed to get capture")
            .immediate_mode(true)
            .open()
            .unwrap();

        // TODO: expand filter
        cap.filter("src port 80 or src port 443", true).unwrap();
        cap.for_each(None, |packet| {
            let frame = ethernet::parse_ethernet_frame(packet.data);

            if frame.ethertype[0] == 0x08 && frame.ethertype[1] == 0x00 {
                let packet = ip::parse_ipv4_packet(frame.payload);
                tx.send(SnifferPacket {
                    src: IpAddr::V4(packet.src),
                    dst: IpAddr::V4(packet.dst),
                    host: ip::translate_ip(IpAddr::V4(packet.src)),
                })
                .expect("sniffer: failed to send ipv4 packet");
            } else if frame.ethertype[0] == 0x86 && frame.ethertype[1] == 0xdd {
                let packet = ip::parse_ipv6_packet(frame.payload);
                tx.send(SnifferPacket {
                    src: IpAddr::V6(packet.src),
                    dst: IpAddr::V6(packet.dst),
                    host: ip::translate_ip(IpAddr::V6(packet.src)),
                })
                .expect("sniffer: failed to send ipv6 packet");
            } else {
                panic!("unsupported ethertype {:?}", frame.ethertype);
            }
        })
        .unwrap();
    }
}
