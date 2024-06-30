// https://en.wikipedia.org/wiki/Ethernet_frame
pub struct EthernetFrame<'a> {
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: [u8; 2],
    pub payload: &'a [u8],
}

pub fn parse_ethernet_frame(data: &[u8]) -> EthernetFrame {
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
