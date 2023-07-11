use std::sync::Arc;

use tokio::{sync::broadcast, net::{UdpSocket, ToSocketAddrs}};
use flume;
pub const DATAGRAM_BYTES_SIZE: usize = 1024;

type Rx = broadcast::Receiver<Vec<u8>>;
type Tx = flume::Sender<Vec<u8>>;
type Sock = Arc<UdpSocket>;

pub fn udp_server(host: impl ToSocketAddrs) -> (Tx, Rx){
    
    todo!()
}