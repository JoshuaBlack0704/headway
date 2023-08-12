use std::{net::{SocketAddr, Ipv4Addr}, fmt::Display};

use aes_siv::{Aes128SivAead, KeyInit, aead::Aead, Nonce};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use tracing::{instrument, error};
use uuid::Uuid;


pub(crate) type NewPeer = (SocketAddr, flume::Receiver<Packet>);

pub const UDP_TGT_HEADER_SIZE: usize = 1024; 

pub fn addr(a:u8, b:u8, c:u8, d:u8, port: u16) -> SocketAddr{
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

#[derive(Clone, Debug)]
pub(crate) struct Packet{
    pub peer: SocketAddr,
    pub data: Vec<u8>,
}


pub(crate) struct AesCipherInfo{
    key: Vec<u8>,
    cipher: Aes128SivAead,
}

impl AesCipherInfo{
    pub(crate) fn new() -> AesCipherInfo {
        let aes_key = Aes128SivAead::generate_key(&mut rand::thread_rng());
        let cipher = Aes128SivAead::new(&aes_key);

        Self{
            key: aes_key.to_vec(),
            cipher,
        }
    }
    pub(crate) fn from_key(key: &[u8]) -> AesCipherInfo {
       Self{
            key: key.to_vec(),
            cipher: Aes128SivAead::new_from_slice(key).expect("Could not get cipher from key"),
        } 
    }
    pub(crate) fn get_key(&self) -> &[u8]{
        &self.key
    }
    pub(crate) fn encrypt(&self, data: &[u8], uuid: &Uuid) -> Vec<u8>{
        let nonce = Nonce::from_slice(uuid.as_bytes().as_slice());
        self.cipher.encrypt(nonce, data).expect("Could not encrypt data")
    }
    pub(crate) fn decrypt(&self, uuid: &Uuid, data: &[u8]) -> Vec<u8>{
        let nonce = Nonce::from_slice(uuid.as_bytes().as_slice());
        self.cipher.decrypt(&nonce, data.as_ref()).expect("Could not decrypt data")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum StrandsPayloadTypes{
    Ack,
    Payload(Vec<u8>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StrandsHeader{
    encrypted: bool,
    uuid: Uuid,
    pkt_count: u64,
    pkt_index: u64,
    payload: StrandsPayloadTypes,
}

impl Display for StrandsHeader{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Strands header: uuid: {}, pkt_count: {}, pkt_index: {}, payload {:?}", self.uuid, self.pkt_count, self.pkt_index, self.payload)
    }
}

impl StrandsHeader{
    #[instrument(skip(cipher, obj))]
    pub(crate) fn packetize(obj: &impl Serialize, cipher: Option<&AesCipherInfo>) -> Vec<StrandsHeader> {
        let uuid = Uuid::new_v4();
        let encrypted;
        
        // Get data
        let msg = match cipher{
            Some(c) => {
                encrypted = true;
                c.encrypt(&Self::serialize_format(obj), &uuid)
            },
            None => {
                encrypted = false;
                Self::serialize_format(obj)
            },
        };
        
        // Split data
        let pkt_count = (msg.len()/UDP_TGT_HEADER_SIZE) + 1;
        let mut headers = Vec::with_capacity(pkt_count);
        
        let mut cursor:usize = 0;
        for x in 0..pkt_count{
            let distance = (msg.len()-cursor).clamp(0, UDP_TGT_HEADER_SIZE);
            headers.push(StrandsHeader { 
                encrypted, 
                uuid, 
                pkt_count: pkt_count as u64, 
                pkt_index: x as u64, 
                payload: StrandsPayloadTypes::Payload(Vec::from(&msg[cursor..cursor+distance]))
            });
            cursor += distance;
        }

        error!("Message {} produced {} pkts from {} bytes", uuid, headers.len(), msg.len());

        headers
    }
    // #[instrument(skip(cipher, pkts))]
    pub(crate) fn depacketize<T: DeserializeOwned + Serialize>(pkts: &mut [StrandsHeader], cipher: &AesCipherInfo) -> Option<T>{
        pkts.sort_unstable_by_key(|h| h.pkt_index);

        if pkts.len() < *pkts[0].get_pkt_count() as usize {
            return None;
        }
        
        let uuid = pkts[0].uuid;
        let encrypted = pkts[0].encrypted;
        
        let mut req_index = 0;
        for pkt in pkts.iter(){
            if pkt.is_ack() {panic!()}
            if pkt.uuid != uuid {return None;}
            if pkt.pkt_index != req_index {return None;}
            req_index += 1;
        }

        let mut msg = Vec::with_capacity(UDP_TGT_HEADER_SIZE * pkts.len());

        for pkt in pkts.iter(){
            match &pkt.payload{
                StrandsPayloadTypes::Payload(p) => {
                    msg.extend_from_slice(p.as_slice());
                },
                _ => {return None;}
            };
        }

        if encrypted{
            return Self::deserialize_format(&cipher.decrypt(&uuid, &msg));
        }
        else{
            return Self::deserialize_format(&msg);
        }
    }
    pub(crate) fn serialize(&self) -> Vec<u8> {
        Self::serialize_format(self)
    }
    pub(crate) fn deserialize(data: &[u8]) -> StrandsHeader{
        Self::deserialize_format(data).unwrap()
    }
    fn serialize_format(obj: &impl Serialize) -> Vec<u8> {
        // serde_json::to_vec(obj).expect("Could not serialize obj")
        postcard::to_allocvec(obj).expect("Could not serialize object") 
    }
    fn deserialize_format<T:DeserializeOwned + Serialize>(data: &[u8]) -> Option<T>{
        // match serde_json::from_slice(data){
        //     Ok(r) => {
        //         return Some(r);
        //     },
        //     Err(_) => return None,
        // }
        match postcard::from_bytes(data){
            Ok(r) => Some(r),
            Err(_) => return None,
        }
    }
    pub(crate) fn get_uuid(&self) -> &Uuid{
       &self.uuid 
    }
    pub(crate) fn get_pkt_count(&self) -> &u64{
        &self.pkt_count
    }
    pub(crate) fn get_pkt_index(&self) -> &u64{
        &self.pkt_index
    }
    pub(crate) fn ack(&self) -> StrandsHeader {
        Self{
            uuid: self.uuid,
            pkt_count: self.pkt_count,
            pkt_index: self.pkt_index,
            payload: StrandsPayloadTypes::Ack,
            encrypted: false,
        }
    }
    pub(crate) fn is_ack(&self) -> bool {
        self.payload == StrandsPayloadTypes::Ack
    }
}

