use std::sync::Arc;
use std::net::SocketAddr;
use tokio::{sync::broadcast::{Receiver, Sender}, net::UdpSocket};

pub type Data = (SocketAddr, Vec<u8>);
type Rx = Receiver<Data>;
type Tx = Sender<Data>;

pub struct UdpTransceiver{
    socket: Arc<UdpSocket>,
    rx: Rx,
}

mod udp_impl;