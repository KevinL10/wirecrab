use std::io::{stdout, Result};

use ratatui::{
    backend::CrosstermBackend,
    crossterm::{
        event::{self, KeyCode, KeyEventKind},
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        ExecutableCommand,
    },
    style::Stylize,
    widgets::Paragraph,
    Terminal,
};

mod dns;
mod ethernet;
mod ip;
mod utils;

const WIFI_DEVICE: &str = "en0";

fn capture_packets() {
    println!("starting capture");
    let devices = pcap::Device::list().expect("devices lookup failed");

    // get the wifi device
    let device = devices
        .into_iter()
        .find(|d| d.name == WIFI_DEVICE)
        .expect("could not get wifi device");

    println!("chose device {:?}", device);

    let mut cap = pcap::Capture::from_device(device)
        .expect("failed to get capture")
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter("src port 80 or src port 443", true).unwrap();
    // cap.filter("host www.testingmcafeesites.com", true).unwrap();

    // let mut count = 0;
    cap.for_each(None, |packet| {
        let frame = ethernet::parse_ethernet_frame(packet.data);
        let packet = ip::parse_ipv4_packet(frame.payload);

        println!(
            "connection from {:?} to {:?} on protocol {:?}",
            ip::translate_ip(packet.src),
            ip::translate_ip(packet.dst),
            packet.protocol
        );
    })
    .unwrap();
}

fn main() {
    capture_packets();
}
