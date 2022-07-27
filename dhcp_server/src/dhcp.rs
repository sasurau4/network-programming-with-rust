use std::net::Ipv4Addr;

use pnet::{packet::PrimitiveValues, util::MacAddr};

const OP: usize = 0;
const HTYPE: usize = 1;
const HLEN: usize = 2;
// const HOPS:usize = 3;
const XID: usize = 4;
const SECS: usize = 8;
const FLAGS: usize = 10;
const CIADDR: usize = 12;
const YIADDR: usize = 16;
const SIADDR: usize = 20;
const GIADDR: usize = 24;
const CHADDR: usize = 28;
const SNAME: usize = 44;
// const FILE: usize = 108;
pub const OPTIONS: usize = 236;
pub struct DhcpServer {
    buffer: Vec<u8>,
}

impl DhcpServer {
    pub fn get_buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    pub fn get_op(&self) -> u8 {
        self.buffer[OP]
    }

    pub fn get_options(&self) -> &[u8] {
        &&self.buffer[OPTIONS..]
    }

    pub fn set_giaddr(&mut self, giaddr: Ipv4Addr) {
        self.buffer[GIADDR..CHADDR].copy_from_slice(&giaddr.octets());
    }

    pub fn set_chaddr(&mut self, chaddr: MacAddr) {
        let t = chaddr.to_primitive_values();
        let macaddr_value = [t.0, t.1, t.2, t.3, t.4, t.5];
        self.buffer[CHADDR..CHADDR + 6].copy_from_slice(&macaddr_value);
    }
}
