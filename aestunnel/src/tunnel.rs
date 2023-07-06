use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use trust_dns_resolver::error::ResolveError;

use crate::ArcLock;

pub const TUNNEL_SERVER_PORT: u16 = 11011;
pub const TUNNEL_PACKET_MAX_SIZE: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum TunnelHeader {
    Open([u8; 32]),
    Secure([u8; 32]),
    Encrypted(Vec<u8>, Vec<u8>),
    KeepAlive,
    Close,
}


#[derive(Debug)]
pub enum TunnelCreateError {
    UdpSockerCreate(std::io::Error),
    Dns(ResolveError),
    Other,
}
pub struct Tunnel {
    uuid: u64,
    sender: flume::Sender<Vec<u8>>,
    receiver: flume::Receiver<Vec<u8>>,
    copies: ArcLock<HashMap<u64, flume::Sender<Vec<u8>>>>,
}

mod tunnel_impl;
mod tunnel_header_impl;

