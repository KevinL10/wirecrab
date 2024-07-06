// https://en.wikipedia.org/wiki/Ethernet_frame
pub struct EthernetFrame<'a> {
    dst: [u8; 6],
    src: [u8; 6],
    pub ethertype: [u8; 2],
    pub payload: &'a [u8],
}

pub fn parse_ethernet_frame(data: &[u8]) -> EthernetFrame {
    let dst: [u8; 6] = data[..6].try_into().expect("error parsing ethernet dst");
    let src: [u8; 6] = data[6..12].try_into().expect("error parsing ethernet src");
    let ethertype: [u8; 2] = data[12..14]
        .try_into()
        .expect("error parsing ethernet ethertype");

    // Check if the ethernet frame has the optional 802.1Q tag
    // https://en.wikipedia.org/wiki/Ethernet_frame#Header
    let payload_start_idx: usize = if ethertype[0] == 0x81 && ethertype[1] == 0x00 {
        18
    } else if ethertype[0] == 0x88 && ethertype[1] == 0xa8 {
        18
    } else {
        14
    };

    let payload: &[u8] = data[payload_start_idx..]
        .try_into()
        .expect("error parsing ethernet payload");

    EthernetFrame {
        dst,
        src,
        ethertype,
        payload,
    }
}
