use std::{sync::Arc, net::SocketAddr};

use log::info;
use tokio::net::UdpSocket;

use crate::{common::{NewPeer, UDP_BUFFER_SIZE}, peer_map::PeerMap};

pub struct UdpServer{
    sock: Arc<UdpSocket>,
    new_peer: flume::Receiver<NewPeer>,
}

impl UdpServer{
    pub async fn new(bind: SocketAddr) -> UdpServer{
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        let (rx, map) = PeerMap::new();
        tokio::spawn(Self::recv(sock.clone(), map));
        Self{
            sock,
            new_peer: rx,
        }
    }
    async fn recv(sock: Arc<UdpSocket>, mut peer_map: PeerMap){
        let mut buffer = vec![0u8;UDP_BUFFER_SIZE];
        
        loop{
            let (len, peer) = match sock.recv_from(&mut buffer).await{
                Ok((l,p)) => (l,p),
                Err(_) => continue,
            };

            let mut pkt:Vec<u8> = Vec::with_capacity(len);
            pkt.extend_from_slice(&buffer[..len]);

            if !peer_map.send(peer, pkt).await{
                return ;
            }
        }
    }
    pub async fn send_to(&self, peer: SocketAddr, data: &[u8]){
        info!("Socket {} sending {} bytes to {}", self.get_local_addr(), data.len(), peer);
        self.sock.send_to(data, peer).await.unwrap();
    }
    pub async fn next_peer(&self) -> NewPeer{
        self.new_peer.recv_async().await.unwrap()
    }
    pub fn get_local_addr(&self) -> SocketAddr{
        self.sock.local_addr().unwrap()
    }
}
