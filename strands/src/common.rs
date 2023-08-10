use std::net::{SocketAddr, Ipv4Addr};

pub type NewPeer = (SocketAddr, flume::Receiver<Packet>);

pub const UDP_BUFFER_SIZE: usize = 1024*1024; 

#[derive(Clone, Debug)]
pub struct Packet{
    pub peer: SocketAddr,
    pub data: Vec<u8>,
}

pub fn addr(a:u8, b:u8, c:u8, d:u8, port: u16) -> SocketAddr{
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}
