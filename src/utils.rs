use crate::ethernet;
use crate::ip;

pub fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<String>()
}
