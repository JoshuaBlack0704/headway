use std::{collections::HashMap, net::SocketAddr};

use crate::common::{NewPeer, Packet};

#[derive(Debug)]
pub(crate) struct PeerMap {
    map: HashMap<SocketAddr, flume::Sender<Packet>>,
    new_peer: flume::Sender<NewPeer>,
}

impl PeerMap {
    pub fn new() -> (flume::Receiver<NewPeer>, PeerMap) {
        let (tx, rx) = flume::unbounded();

        let map = PeerMap {
            map: HashMap::new(),
            new_peer: tx,
        };

        (rx, map)
    }
    pub(crate) async fn send(&mut self, peer: SocketAddr, data: Vec<u8>) -> bool {
        if !self.map.contains_key(&peer) {
            let (tx, rx) = flume::unbounded();
            if let Err(_) = self.new_peer.send_async((peer, rx)).await {
                return self.map.len() == 0;
            }
            self.map.insert(peer, tx);
        }

        if let Err(_) = self
            .map
            .get(&peer)
            .unwrap()
            .send_async(Packet { peer, data })
            .await
        {
            self.map.remove(&peer);
        }

        true
    }
}
