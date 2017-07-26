extern crate rlp;
extern crate secp256k1;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate clap;
extern crate rand;
extern crate crypto;

use std::io::{ self, Read, Write };
use std::net::{ Ipv4Addr, AddrParseError };
use std::ops::Deref;
use std::time;
use std::net::UdpSocket;
use std::fs::File;
use std::str::FromStr;
use std::thread;
use std::any::Any;
use std::marker::Send;
use std::sync::Arc;

use rlp::{ Encodable, RlpStream };

use secp256k1::{ Secp256k1, Message };
use secp256k1::key::SecretKey;

use rand::OsRng;

use crypto::sha3::Sha3;
use crypto::digest::Digest;

lazy_static! {
    static ref SECP: Secp256k1 = Secp256k1::new();
}

enum Error {
    IOError(io::Error),
    SECP256K1Error(secp256k1::Error),
    AddrParseError(AddrParseError),
    ThreadError(Box<Any + Send>),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::SECP256K1Error(e)
    }
}

impl From<AddrParseError> for Error {
    fn from(e: AddrParseError) -> Self {
        Error::AddrParseError(e)
    }
}

impl From<Box<Any + Send>> for Error {
    fn from(e: Box<Any + Send>) -> Self {
        Error::ThreadError(e)
    }
}

//only ipv4 for now:
#[derive(Clone, Copy)]
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
        s.begin_unbounded_list();
        self.address.octets().to_vec().rlp_append(s);
        self.udp_port.rlp_append(s);
        self.tcp_port.rlp_append(s);
        s.complete_unbounded_list();
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
        s.begin_unbounded_list();
        0x3u8.rlp_append(s);
        self.from.rlp_append(s);
        self.to.rlp_append(s);
        let ts = time::SystemTime::now() + time::Duration::new(60, 0);
        match ts.duration_since(time::UNIX_EPOCH) {
            Ok(t) => (t.as_secs() as u32).rlp_append(s),
            Err(_) => panic!("damn"),
        }
        s.complete_unbounded_list();
    }
}

fn keccak256(data: &[u8]) -> [u8; 256 / 8] {
    let mut sha3 = Sha3::keccak256();
    sha3.input(data);
    let mut out = [0; 256 / 8];
    sha3.result(&mut out);
    out
}

struct PingServer {
    endpoint: Endpoint,
    private_key: SecretKey,
    socket: UdpSocket,
}

impl PingServer {
    fn new(endpoint: Endpoint, private_key_path: &str) -> Result<PingServer, Error> {
        // read private key
        let private_key_raw = {
            let mut f = File::open(private_key_path)?;
            let mut b = vec![];
            f.read_to_end(&mut b)?;
            b
        };
        let private_key = SecretKey::from_slice(&SECP, &private_key_raw)?;

        //setup socket
        println!("listening on {}...", endpoint.udp_port);
        let socket = UdpSocket::bind(("0.0.0.0", endpoint.udp_port))?;

        Ok(PingServer{ endpoint, private_key, socket })
    }

    fn mk_packet(&self, node: PingNode) -> Result<Vec<u8>, Error> {
        let message = [vec![0x01], rlp::encode(&node).to_vec()].concat();
        let message_hash = keccak256(&message);
        let signature = SECP.sign_recoverable(&Message::from_slice(&message_hash)?, &self.private_key)?;
        let (recovery_id, signature_raw) =  signature.serialize_compact(&SECP);
        let payload = [signature_raw.to_vec(), vec![recovery_id.to_i32() as u8], message].concat();
        let payload_hash = keccak256(&payload);
        let packet = [payload_hash.to_vec(), payload].concat();
        Ok(packet)
    }

    fn udp_listen(&self) -> Result<(), Error> {
        loop {
            let mut buf = [0; 1500];
            let (length, addr) = self.socket.recv_from(&mut buf)?;
            println!("{}: {:?}", addr, buf[..length].to_vec());
        }
    }

    fn ping(&self, endpoint: Endpoint) -> Result<(), Error> {
        let ping = PingNode::new(self.endpoint, endpoint);
        let packet = self.mk_packet(ping)?;
        println!("sending ping");
        let _size = self.socket.send_to(&packet, (endpoint.address, endpoint.udp_port))?;
        Ok(())
    }
}

fn ma1n() -> Result<(), Error> {
    let matches = clap_app!(ndscrwlr =>
        (version: "0.1")
        (author: "Stefan Nitz <nitz.stefan@googlemail.com>")
        (about: "crawls some nodes")
        (@arg KEYFILE: "The file containing your private key (default: key.priv)")
        (@arg generate: -g --generate ... "Generate a new private key (may overwrite KEYFILE)")
    ).get_matches();

    let private_key_path = matches.value_of("KEYFILE").unwrap_or("key.priv");
    println!("using private key file: {}", private_key_path);
    if matches.is_present("generate") {
        println!("generating new key...");
        let key = SecretKey::new(&SECP, &mut OsRng::new()?);
        let key_raw = &key[..];
        let mut f = File::create(private_key_path)?;
        f.write(key_raw)?;
    }
    let my_address = Ipv4Addr::from_str("127.0.0.1")?;
    let my_endpoint = Endpoint::new(my_address, 30303, 30303);
    let other_address = Ipv4Addr::from_str("13.93.211.84")?;
    let other_endpoint = Endpoint::new(other_address, 30303, 30303);
    let server = Arc::new(PingServer::new(my_endpoint, private_key_path)?);
    let thread_server = server.clone();
    let t = thread::spawn(move || thread_server.udp_listen());
    server.ping(other_endpoint)?;
    let _: () = t.join()??;
    Ok(())
}


fn main() {
    match ma1n() {
        Ok(()) => (),
        Err(_) => println!("an error occured and i was too lazy to implement the debug trait on it"),
    }
}
