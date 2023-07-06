use std::fmt::Display;

use super::TunnelHeader;


impl Display for TunnelHeader{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self{
            TunnelHeader::Open(k) => write!(f, "Tunnel Header Open: {:?}", k),
            TunnelHeader::Encrypted(n, e) => write!(f, "Tunnel Header Encrypted: Nonce: {:?} Msg: {:?}", n, e),
            TunnelHeader::KeepAlive => write!(f, "Tunnel Header KeepAlive"),
            TunnelHeader::Close => write!(f, "Tunnel Header Clone"),
            TunnelHeader::Secure(k) => write!(f, "Tunnel Header Secured: Key: {:?}", k),
        }
    }
}