extern crate rlp;

use std::net::Ipv4Addr as _Ipv4Addr;
use std::ops::Deref;
use std::time;

use rlp::{ Encodable, RlpStream };

struct Ipv4Addr(_Ipv4Addr);

impl Deref for Ipv4Addr {
    type Target = _Ipv4Addr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encodable for Ipv4Addr {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut bytes = vec![0x84];
        bytes.extend_from_slice(&self.octets());
        s.append_raw(&bytes, 1);
    }
}

//only ipv4 for now:
struct Endpoint {
    address: Ipv4Addr,
    udp_port: u16,
    tcp_port: u16,
}

impl Endpoint {
    fn new(address: Ipv4Addr, udp_port: u16, tcp_port: u16) -> Endpoint {
        Endpoint{ address, udp_port, tcp_port }
    }
}

impl Encodable for Endpoint {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        self.address.rlp_append(s);
        self.udp_port.rlp_append(s);
        self.tcp_port.rlp_append(s);
    }
}

struct PingNode {
    from: Endpoint,
    to: Endpoint,
}

impl PingNode {
    fn new(from: Endpoint, to: Endpoint) -> PingNode {
        PingNode{ from, to }
    }
}

impl Encodable for PingNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        0x01u8.rlp_append(s);
        self.from.rlp_append(s);
        self.to.rlp_append(s);
        match time::SystemTime::now().elapsed() {
            Ok(t) => (t.as_secs() as u32).rlp_append(s),
            Err(_) => panic!("damn"),
        }

    }
}

struct PingServer {
    endpoint: Endpoint,
    private_key: 
}

impl PingServer {
    fn new(endpoint: Endpoint) -> PingServer {
        PingServer{ endpoint }
    }
}

fn main() {
    println!("Hello, world!");
}
