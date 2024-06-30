use std::sync::Arc;
use std::sync::Mutex;

use crate::ethernet;
use crate::ip;

const WIFI_DEVICE: &str = "en0";

// hosts is a vec of resolved source IPs that we've connected to
// TODO: replace with tx,rx
pub fn start_packet_capture(hosts: Arc<Mutex<Vec<String>>>) {
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
    cap.filter("host www.testingmcafeesites.com", true).unwrap();

    // let mut count = 0;
    cap.for_each(None, |packet| {
        let frame = ethernet::parse_ethernet_frame(packet.data);
        let packet = ip::parse_ipv4_packet(frame.payload);

        // println!("{}", ip::translate_ip(packet.src));
        println!(
            "connection from {:?} to {:?} on protocol {:?}",
            ip::translate_ip(packet.src),
            ip::translate_ip(packet.dst),
            packet.protocol
        );

        // {
        //     let mut data = hosts.lock().unwrap();
        //     (*data).push(ip::translate_ip(packet.src));
        // }
    })
    .unwrap();
}
