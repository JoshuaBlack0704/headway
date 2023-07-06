use std::{sync::Arc, net::SocketAddr};

use log::debug;
use tokio::{sync::broadcast::{self, error::RecvError}, net::{UdpSocket, ToSocketAddrs}};

use crate::tunnel::TUNNEL_PACKET_MAX_SIZE;

use super::{UdpTransceiver, Tx};

impl UdpTransceiver{
    pub async fn new<const Cap: usize>(bind_to: impl ToSocketAddrs) -> UdpTransceiver {
        let sock = Arc::new(UdpSocket::bind(bind_to).await.expect("Could not create Upd socket"));
        let (tx, rx) = broadcast::channel(Cap); 

        tokio::spawn(Self::recv_task(tx, sock.clone()));

        Self{
            socket: sock,
            rx,
        }
    }

    pub async fn recv(&mut self) -> Result<(SocketAddr, Vec<u8>), RecvError> {
        self.rx.recv().await
    }

    async fn recv_task(tx: Tx, sock: Arc<UdpSocket>){
        debug!("Udp socket {} started receiver", sock.local_addr().unwrap());
        loop{
            let mut buf = [0u8; TUNNEL_PACKET_MAX_SIZE];
            let client;
            let len;

            match sock.recv_from(&mut buf).await{
                Ok((_len, _client)) => {
                    client = _client;
                    len = _len;
                },
                Err(_) => {continue;},
            }

            let data = buf[0..len].to_vec();
            debug!("Udp socket {} get msg from {}", sock.local_addr().unwrap(), client);

            if let Err(_) = tx.send((client, data)){
                debug!("Udp socket {} stopping receiver", sock.local_addr().unwrap());
                return;
            }
        }
    }
}

#[cfg(test)]
mod udp_transceiver{
    use crate::udp::UdpTransceiver;

    #[test]
    fn one_way(){
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let src = UdpTransceiver::new("0.0.0.0:4041");
        let dst = UdpTransceiver::new("0.0.0.0:4042");
    }
}