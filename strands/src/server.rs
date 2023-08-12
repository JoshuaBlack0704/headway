use std::{net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;
use tracing::{debug, instrument};

use crate::{
    common::{NewPeer, UDP_TGT_HEADER_SIZE},
    peer_map::PeerMap,
};

pub struct UdpServer {
    sock: Arc<UdpSocket>,
    new_peer: flume::Receiver<NewPeer>,
}

impl UdpServer {
    pub async fn new(bind: SocketAddr) -> UdpServer {
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        let (rx, map) = PeerMap::new();
        tokio::spawn(Self::recv(sock.clone(), map));
        Self { sock, new_peer: rx }
    }
    #[instrument(skip(sock, peer_map))]
    async fn recv(sock: Arc<UdpSocket>, mut peer_map: PeerMap) {
        let mut buffer = vec![0u8; UDP_TGT_HEADER_SIZE * 10];

        loop {
            let (len, peer) = match sock.recv_from(&mut buffer).await {
                Ok((l, p)) => (l, p),
                Err(_) => continue,
            };

            let mut pkt: Vec<u8> = Vec::with_capacity(len);
            pkt.extend_from_slice(&buffer[..len]);

            if !peer_map.send(peer, pkt).await {
                return;
            }
            debug!(
                "Socket {} got {} bytes from peer {}",
                sock.local_addr().unwrap(),
                len,
                peer
            );
        }
    }
    #[instrument(skip(self, peer, data))]
    pub async fn send_to(&self, peer: SocketAddr, data: &[u8]) {
        self.sock.send_to(data, peer).await.unwrap();
    }
    #[instrument(skip(self), ret)]
    pub(crate) async fn next_peer(&self) -> NewPeer {
        self.new_peer.recv_async().await.unwrap()
    }
    pub fn get_local_addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap()
    }
    pub fn get_socket(&self) -> Arc<UdpSocket> {
        self.sock.clone()
    }
}
