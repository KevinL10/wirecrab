const WIFI_DEVICE: &str = "en0";

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

    cap.filter("host www.testingmcafeesites.com", true).unwrap();

    let mut count = 0;
    cap.for_each(None, |packet| {
        println!(
            "Got {:?} {:?}",
            packet.header,
            String::from_utf8_lossy(packet.data)
        );
        count += 1;
        if count > 100 {
            panic!("got 100 packets");
        }
    })
    .unwrap();
}
