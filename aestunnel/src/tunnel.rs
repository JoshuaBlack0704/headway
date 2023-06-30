use std::{net::{SocketAddr, IpAddr}, collections::HashMap, sync::Arc};

use aes_gcm_siv::{Aes128GcmSiv, KeyInit, Key, aead::Aead, Nonce, AeadCore};
use local_ip_address::local_ip;
use log::{debug, info};
use rand::{thread_rng, Rng};
use tokio::{net::UdpSocket, sync::RwLock, time::sleep};
use trust_dns_resolver::{TokioAsyncResolver, error::ResolveError, lookup_ip::LookupIp};
use url::Url;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{Tunnel, TUNNEL_SERVER_PORT, TunnelCreateError, TUNNEL_PACKET_MAX_SIZE, TunnelHeader, ArcLock};

pub(crate) async fn dns_lookup(url: Url) -> Result<LookupIp, ResolveError>{
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
    resolver.lookup_ip(url.host_str().expect("Target server does not have a host string")).await
}

impl Tunnel{
    pub async fn send(&self, msg: Vec<u8>){
        let _ = self.sender.send_async(msg).await;
        sleep(tokio::time::Duration::from_secs(1)).await;
    }
    // The server function will wait until a successful key exchange has occured
    pub async fn server() -> Result<Tunnel, TunnelCreateError>{
        let uuid:u64 = thread_rng().gen();
        let (tx, rx) = flume::unbounded();
        let map = Arc::new(RwLock::new(HashMap::new()));
        let trx;
        {
            let (tx, rx) = flume::unbounded();
            trx = rx;
            map.write().await.insert(uuid, tx);
        }
        let mut buf = [0u8; TUNNEL_PACKET_MAX_SIZE];
        
       
        // We need a udp socket
        let local_ip = match local_ip(){
            Ok(ip) => ip,
            Err(e) => return Err(TunnelCreateError::LocalIp(e)),
        };

        let sock = match UdpSocket::bind((local_ip, TUNNEL_SERVER_PORT)).await{
            Ok(s) => s,
            Err(e) => return Err(TunnelCreateError::UdpSockerCreate(e)),
        };
        let sock = Arc::new(sock);
        //
        
        // Listen
        loop{
            
            let private_key = EphemeralSecret::new(rand_core::OsRng);
            let public_key = PublicKey::from(&private_key);
            let their_key;
            let shared_key;
            
            debug!("Tunnel {} waiting for open request", uuid);
            
            // The first step is an open request.
            // The server must respond with a secure request
            let (_, client) = match sock.recv_from(&mut buf).await{
                Ok(c) => c,
                Err(_) => continue,
            };
            match bincode::deserialize::<TunnelHeader>(&buf){
                Ok(TunnelHeader::Open(key)) => {
                    debug!("Tunnel {} got open request", uuid);
                    their_key = PublicKey::from(key);
                    shared_key = private_key.diffie_hellman(&their_key);

                    let secure = match bincode::serialize(&TunnelHeader::Secure(public_key.to_bytes())){
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    sock.send_to(&secure, client).await.expect("Sock error");
                    
                },
                _ => continue,
            }

            // Next we wait for the first keep alive request to start the tunnel async             
            let (_, _client) = match sock.recv_from(&mut buf).await{
                Ok(c) => c,
                Err(_) => continue,
            };
            if client != _client{
                continue;
            }
            match bincode::deserialize::<TunnelHeader>(&buf){
                Ok(TunnelHeader::KeepAlive) => {
                    tokio::spawn(Self::tunnel_rcv(sock.clone(), shared_key.to_bytes(), client, map.clone()));
                    tokio::spawn(Self::tunnel_snd(sock, shared_key.to_bytes(), client, rx));
                    info!("Tunnel successfuly created!");
                    
                    return Ok(Tunnel{
                        uuid,
                        sender: tx,
                        receiver: trx,
                        copies: map,
                    });
                },
                _ => continue,
            }
        }
        // The first step is to wait for an open packet

    }

    pub async fn tunnel_rcv(sock: Arc<UdpSocket>, shared_key: [u8; 32], their_addr: SocketAddr, tunnels: ArcLock<HashMap<u64, flume::Sender<Vec<u8>>>>){
        let cipher_key = Key::<Aes128GcmSiv>::from_slice(&shared_key[0..16]);
        let cipher = Aes128GcmSiv::new(&cipher_key);
        
        let alive = match bincode::serialize(&TunnelHeader::KeepAlive){
            Ok(a) => a,
            Err(_) => return ,
        };
        
        if let Err(_) = sock.send_to(&alive, their_addr).await{return;}

        let mut buf = [0u8; TUNNEL_PACKET_MAX_SIZE];
        
        while let Ok((_, client)) = sock.recv_from(&mut buf).await{
            if client != their_addr{continue;}
            let msg = match bincode::deserialize(&buf){
                Ok(m) => m,
                Err(_) => continue,
            };
            
            if let TunnelHeader::Close = msg{
                return;
            }

            if let TunnelHeader::Encrypted(nonce, emsg) = msg{
                let dmsg = match cipher.decrypt(&Nonce::from_slice(&nonce), emsg.as_ref()){
                    Ok(d) => d,
                    Err(_) => continue,
                };

                debug!("Tunnel received {:?} from {:?}", dmsg, their_addr);

                for t in tunnels.read().await.values(){
                    let _ = t.send_async(dmsg.clone()).await;
                }
            }
        }
    }

    async fn tunnel_snd(sock: Arc<UdpSocket>, shared_key: [u8; 32], their_addr: SocketAddr, rx: flume::Receiver<Vec<u8>>){
        let cipher_key = Key::<Aes128GcmSiv>::from_slice(&shared_key[0..16]);
        let cipher = Aes128GcmSiv::new(&cipher_key);
        
        while let Ok(msg) = rx.recv_async().await{
            let nonce = Aes128GcmSiv::generate_nonce(&mut aes_gcm_siv::aead::OsRng);
            let emsg = match cipher.encrypt(&nonce, msg.as_ref()){
                Ok(e) => e,
                Err(_) => continue,
            };
            
            if let Ok(bytes) = bincode::serialize(&TunnelHeader::Encrypted(nonce.to_vec(), emsg)){
                let _ = sock.send_to(&bytes, &their_addr).await;
            }
        }
    }
    
    // Will attempt ot connect to a server
    pub async fn client(url: Url) -> Result<Tunnel, TunnelCreateError>{
        let tgt = match dns_lookup(url).await{
            Ok(t) => t,
            Err(e) => return Err(TunnelCreateError::Dns(e)),
        }.iter().collect::<Vec<IpAddr>>();
        // init
        let tgt = SocketAddr::from((tgt[0], TUNNEL_SERVER_PORT));
        let private_key = EphemeralSecret::new(rand_core::OsRng);
        let public_key = PublicKey::from(&private_key);
        let their_key;
        let shared_key;
        let uuid:u64 = thread_rng().gen();
        let (tx, rx) = flume::unbounded();
        let map = Arc::new(RwLock::new(HashMap::new()));
        let trx;
        {
            let (tx, rx) = flume::unbounded();
            trx = rx;
            map.write().await.insert(uuid, tx);
        }
        //
        
        debug!("Tunnel {} atempting to connect to {}", uuid, tgt);
        
        // We need a udp socket
        let local_ip = match local_ip(){
            Ok(ip) => ip,
            Err(e) => return Err(TunnelCreateError::LocalIp(e)),
        };

        let sock = match UdpSocket::bind((local_ip, 0)).await{
            Ok(s) => s,
            Err(e) => return Err(TunnelCreateError::UdpSockerCreate(e)),
        };
        let sock = Arc::new(sock);
        //

        // Open
        let bytes = match bincode::serialize(&TunnelHeader::Open(public_key.to_bytes())){
            Ok(b) => b,
            Err(_) => return Err(TunnelCreateError::Other),
        };
        let _ = sock.send_to(&bytes, tgt).await;
        debug!("Tunnel {} sent open to {}", uuid, tgt);
        //

        // Secure
        let mut buf = [0u8; TUNNEL_PACKET_MAX_SIZE];
        let (_, client) = match sock.recv_from(&mut buf).await{
            Ok(c) => c,
            Err(_) => return Err(TunnelCreateError::Other),
        };
        match bincode::deserialize::<TunnelHeader>(&buf){
            Ok(TunnelHeader::Secure(key)) => {
                their_key = PublicKey::from(key);
                shared_key = private_key.diffie_hellman(&their_key);
                
                tokio::spawn(Self::tunnel_rcv(sock.clone(), shared_key.to_bytes(), client, map.clone()));
                tokio::spawn(Self::tunnel_snd(sock, shared_key.to_bytes(), client, rx));

                return Ok(Tunnel{
                    uuid,
                    sender: tx,
                    receiver: trx,
                    copies: map.clone(),
                });
            },
            _ => return Err(TunnelCreateError::Other),
        }
        //

    }
}

impl Clone for Tunnel{
    fn clone(&self) -> Self {
        let uuid = thread_rng().gen();
        let (tx, rx) = flume::unbounded();

        self.copies.blocking_write().insert(uuid, tx);
        
        Tunnel{
            uuid,
            sender: self.sender.clone(),
            receiver: rx,
            copies: self.copies.clone(),
        }
    }
}

impl Drop for Tunnel{
    fn drop(&mut self) {
        let c = self.copies.clone();
        let uuid = self.uuid.clone();
        tokio::spawn(async move {
            c.write().await.remove(&uuid);
        });
    }
}