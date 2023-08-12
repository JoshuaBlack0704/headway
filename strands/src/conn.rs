use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, sync::Arc};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rsa::{sha2, Oaep, RsaPrivateKey};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{net::UdpSocket, time::Duration};
use tracing::{debug, info, instrument, trace};
use trust_dns_resolver::AsyncResolver;
use uuid::Uuid;

use crate::{
    common::{addr, AesCipherInfo, Packet, StrandsHeader, UDP_TGT_HEADER_SIZE},
    server::UdpServer,
};

pub struct Connection<T: Serialize + DeserializeOwned + 'static> {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    cipher: AesCipherInfo,
    rx: flume::Receiver<Packet>,
    msg_map: HashMap<Uuid, Vec<StrandsHeader>>,
    _t: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Connection<T> {
    pub async fn next_conn(socket: &UdpServer) -> Self {
        let (peer, rx) = socket.next_peer().await;

        let mut connection = Self {
            sock: socket.get_socket(),
            peer,
            rx,
            cipher: AesCipherInfo::new(),
            msg_map: HashMap::new(),
            _t: PhantomData,
        };

        connection.server_secure().await;

        connection
    }

    #[instrument]
    pub async fn connect_to(tgt: &str, port: u16) -> Self {
        let sock = Arc::new(UdpSocket::bind(addr(0, 0, 0, 0, 0)).await.unwrap());

        let resolver =
            AsyncResolver::tokio_from_system_conf().expect("Could not get host dns resolver");

        let ip = resolver
            .lookup_ip(tgt)
            .await
            .expect("Could not resolve tgt")
            .iter()
            .next()
            .expect("Could not get one ip");

        let peer = SocketAddr::new(ip, port);
        sock.connect(peer)
            .await
            .expect("Could not filter udp socket");

        let (tx, rx) = flume::unbounded();

        tokio::spawn(Self::client_recv(sock.clone(), tx));

        let mut connection = Self {
            sock,
            peer,
            rx,
            cipher: AesCipherInfo::new(),
            msg_map: HashMap::new(),
            _t: PhantomData,
        };

        connection.client_secure().await;

        connection
    }

    #[instrument(skip(self))]
    async fn client_secure(&mut self) {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let pvk = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to gen key");
        let pbk = pvk.to_public_key();
        let padding = Oaep::new::<sha2::Sha256>();

        let key = pbk
            .encrypt(&mut rand::thread_rng(), padding, self.cipher.get_key())
            .expect("Could not encrypt aes key");
        self.send_aes_key(&key).await;
        info!(
            "Socket {} established secure connection with {}",
            self.get_local_addr(),
            self.peer
        );
    }

    #[instrument(skip(self))]
    async fn server_secure(&mut self) {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let pvk = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to gen key");
        let padding = Oaep::new::<sha2::Sha256>();

        let key = pvk
            .decrypt(padding, self.next_type::<Vec<u8>>().await.as_slice())
            .expect("Could not descrypt aes key");

        self.cipher = AesCipherInfo::from_key(&key);
        self.rx.drain();
        info!(
            "Socket {} established secure connection with {}",
            self.get_local_addr(),
            self.peer
        );
    }

    #[instrument(skip(self))]
    async fn filtered_next_packet(&mut self) -> Uuid {
        loop {
            let pkt = self.rx.recv_async().await.expect("Channel Error");
            if pkt.peer != self.peer {
                continue;
            }

            let header = StrandsHeader::deserialize(&pkt.data);
            let uuid = header.get_uuid().clone();

            if !header.is_ack() {
                trace!(
                    "Socket {} sending ACK{} to {} for message {}",
                    self.get_local_addr(),
                    header.get_pkt_index(),
                    self.peer,
                    uuid
                );
                let pkts = [header.ack()];
                self.send_pkts(&pkts).await;
            }

            if !self.msg_map.contains_key(&uuid) {
                self.msg_map.insert(uuid, vec![]);
            }

            self.msg_map.get_mut(&uuid).unwrap().push(header);

            return uuid;
        }
    }

    #[instrument(skip(self, pkts))]
    async fn send_pkts(&self, pkts: &[StrandsHeader]) {
        for pkt in pkts.iter() {
            self.sock
                .send_to(pkt.serialize().as_slice(), self.peer)
                .await
                .expect("Could not send packet");
        }
        trace!("Sending {} pkts to {}", pkts.len(), self.peer);
    }

    #[instrument(skip(self, pkts))]
    async fn reliable_exchange(&mut self, mut pkts: Vec<StrandsHeader>) {
        let uuid = pkts[0].get_uuid().clone();
        let mut _last_uuid = Uuid::new_v4();
        let mut interval = tokio::time::interval(Duration::from_millis(100));

        while pkts.len() > 0 {
            tokio::select! {
                _ = interval.tick() => {
                    self.send_pkts(&pkts).await;
                    continue;
                }
                val = self.filtered_next_packet() => {
                    _last_uuid = val
                }
            };

            if _last_uuid == uuid {
                let ack = self
                    .msg_map
                    .remove(&uuid)
                    .expect("Critial error here")
                    .remove(0);
                if !ack.is_ack() {
                    // TEMPORARY
                    panic!();
                }
                trace!(
                    "Socket {} got ACK{} for message {} from {}",
                    self.get_local_addr(),
                    ack.get_pkt_index(),
                    uuid,
                    self.peer
                );
                if let Ok(index) =
                    pkts.binary_search_by_key(ack.get_pkt_index(), |p| *p.get_pkt_index())
                {
                    pkts.remove(index);
                }
            }
        }
    }

    #[instrument(skip(self, obj))]
    pub async fn send_reliable_encrypted(&mut self, obj: &T) {
        let pkts = StrandsHeader::packetize(obj, Some(&self.cipher));
        self.reliable_exchange(pkts).await;
    }
    #[instrument(skip(self, obj))]
    pub async fn send_reliable_unencrypted(&mut self, obj: &T) {
        let pkts = StrandsHeader::packetize(obj, None);
        self.reliable_exchange(pkts).await;
    }
    #[instrument(skip(self, obj))]
    pub async fn send_unreliable_encrypted(&self, obj: &T) -> Uuid {
        let pkts = StrandsHeader::packetize(obj, Some(&self.cipher));
        self.send_pkts(&pkts).await;
        pkts[0].get_uuid().clone()
    }
    #[instrument(skip(self, obj))]
    pub async fn send_unreliable_unencrypted(&self, obj: &T) -> Uuid {
        let pkts = StrandsHeader::packetize(obj, None);
        self.send_pkts(&pkts).await;
        pkts[0].get_uuid().clone()
    }
    async fn send_aes_key(&mut self, obj: &(impl Serialize + DeserializeOwned)) {
        let pkts = StrandsHeader::packetize(obj, None);
        self.reliable_exchange(pkts).await;
    }
    async fn next_type<K: Serialize + DeserializeOwned>(&mut self) -> K {
        let mut ret: Option<K> = None;
        let mut uuid = Uuid::new_v4();

        while let None = ret {
            uuid = self.filtered_next_packet().await;
            let pkts = self.msg_map.get_mut(&uuid).unwrap();
            ret = StrandsHeader::depacketize::<K>(pkts, &self.cipher);
        }

        self.msg_map.remove(&uuid);
        ret.unwrap()
    }

    #[instrument(skip(self))]
    pub async fn next_msg(&mut self) -> T {
        return self.next_type().await;
    }

    #[instrument(skip(sock, tx))]
    async fn client_recv(sock: Arc<UdpSocket>, tx: flume::Sender<Packet>) {
        let mut buffer = vec![0u8; UDP_TGT_HEADER_SIZE * 5];
        loop {
            let (len, peer) = match sock.recv_from(&mut buffer).await {
                Ok((l, p)) => (l, p),
                Err(_) => continue,
            };

            debug!(
                "Socket {} got {} bytes from peer {}",
                sock.local_addr().unwrap(),
                len,
                peer
            );

            let mut data: Vec<u8> = Vec::with_capacity(len);
            data.extend_from_slice(&buffer[..len]);

            if let Err(_) = tx
                .send_async(Packet {
                    peer,
                    data: data.clone(),
                })
                .await
            {
                return;
            }
        }
    }

    #[instrument(skip(self))]
    pub fn get_local_addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap()
    }
}
