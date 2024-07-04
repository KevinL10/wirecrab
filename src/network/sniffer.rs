use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;

use pcap::Device;

use crate::network::ethernet;
use crate::network::ip;

pub struct SnifferPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
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

    pub fn start_packet_capture(&self, tx: Sender<SnifferPacket>) {
        let mut cap = pcap::Capture::from_device(self.device.clone())
            .expect("failed to get capture")
            .immediate_mode(true)
            .open()
            .unwrap();

        cap.filter("ip and (src port 80 or src port 443)", true)
            .unwrap();
        // cap.filter("host www.testingmcafeesites.com", true).unwrap();
        // cap.filter("host app.todoist.com", true).unwrap();

        // let mut count = 0;
        cap.for_each(None, |packet| {
            let frame = ethernet::parse_ethernet_frame(packet.data);
            let packet = ip::parse_ipv4_packet(frame.payload);
            tx.send(SnifferPacket {
                src: packet.src,
                dst: packet.dst,
                host: ip::translate_ip(packet.src),
            })
            .expect("sniffer: failed to send packet");

            // println!("{:?} {:?}", packet.src, packet.dst);
            // if (packet.src.octets()[0] == 0) {
            //     println!("{:?}", packet);
            // }
        })
        .unwrap();
    }
}
