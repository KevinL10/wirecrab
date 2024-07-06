#[allow(dead_code)]
#[derive(Debug)]
pub struct UdpDatagram<'a> {
    pub src: u16,    // 16 bits
    pub dst: u16,    // 16 bits
    pub length: u16, // 16 bits
    checksum: u16,   // 16 bits
    pub data: &'a [u8],
}

// TODO: verify checksum
pub fn parse_udp_packet(data: &[u8]) -> UdpDatagram {
    let src = u16::from_be_bytes([data[0], data[1]]);
    let dst = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);
    let data = &data[8..];

    assert!(data.len() == (length - 8) as usize);

    UdpDatagram {
        src,
        dst,
        length,
        checksum,
        data,
    }
}
