use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use trust_dns_resolver::error::ResolveError;

pub const TUNNEL_SERVER_PORT: u16 = 11011;
pub const TUNNEL_PACKET_MAX_SIZE: usize = 1024;
type ArcLock<T> = Arc<RwLock<T>>;

#[derive(Debug, Serialize, Deserialize)]
pub enum TunnelHeader {
    Open([u8; 32]),
    Secure([u8; 32]),
    Encrypted(Vec<u8>, Vec<u8>),
    KeepAlive,
    Close,
}

mod tunnel_header;

#[derive(Debug)]
pub enum TunnelCreateError {
    LocalIp(local_ip_address::Error),
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

mod tunnel;

#[cfg(test)]
mod key_exchange {
    use rand::rngs::OsRng;
    use aes_gcm_siv::{Key, Aes128GcmSiv, KeyInit, AeadCore, aead::Aead};
    use std::net::IpAddr;

    use tokio::runtime;
    use url::Url;
    // use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    use crate::{tunnel, Tunnel};

    #[test]
    fn key_swap() {
        let s1 = EphemeralSecret::new(rand_core::OsRng);
        let s1p = PublicKey::from(&s1);

        let s2 = EphemeralSecret::new(rand_core::OsRng);
        let s2p = PublicKey::from(&s2);

        let s1s = s1.diffie_hellman(&s2p);
        let s2s = s2.diffie_hellman(&s1p);

        println!(
            "Secret Keys:\n\n {:?}\n{:?}",
            s1s.to_bytes(),
            s2s.to_bytes()
        );
        assert_eq!(s1s.to_bytes(), s2s.to_bytes());
    }

    #[test]
    fn aes_swap() {
        let s1 = EphemeralSecret::new(rand_core::OsRng);
        let s1p = PublicKey::from(&s1);

        let s2 = EphemeralSecret::new(rand_core::OsRng);
        let s2p = PublicKey::from(&s2);

        let s1s = s1.diffie_hellman(&s2p).to_bytes();
        let s2s = s2.diffie_hellman(&s1p).to_bytes();

        let _msg = String::from("Encrypted -- Decrypted");

        let k1 = Key::<Aes128GcmSiv>::from_slice(&s1s[0..16]);
        let k2 = Key::<Aes128GcmSiv>::from_slice(&s2s[0..16]);

        let c1 = Aes128GcmSiv::new(&k1);
        let c2 = Aes128GcmSiv::new(&k2);

        let nonce = Aes128GcmSiv::generate_nonce(&mut OsRng);

        let emsg = c1
            .encrypt(&nonce, _msg.as_bytes())
            .expect("Could not encrypt");
        let dmsg = c2
            .decrypt(&nonce, emsg.as_ref())
            .expect("Could not decrypt");
        let msg = String::from_utf8(dmsg.clone()).expect("Could not create utf8 string");

        println!("Decrypted message: {}\nFrom: {:?}", msg, dmsg);
        assert_eq!(_msg, msg);
    }

    #[test]
    fn dns_lookup() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Could not create tokio runtime");
        let url = Url::parse("https://localhost").expect("Could not parse url");
        let response = rt
            .block_on(tunnel::dns_lookup(url.clone()))
            .expect(&format!("Could not lookup url: {}", url))
            .iter()
            .collect::<Vec<IpAddr>>();
        println!("Resloved hostname for {}: {:?}", url, response);
        assert_eq!(format!("{}", response[0]), "127.0.0.1");
    }

    #[test]
    fn round_trip() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Could not create tokio runtime");
        rt.spawn(Tunnel::server());
        let _ = rt.block_on(Tunnel::client(Url::parse("http://localhost").unwrap()));
    }
}
