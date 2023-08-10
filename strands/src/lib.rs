pub mod common;
pub(crate) mod peer_map;
pub mod server;



struct UdpConnection{
}

struct ReliableExchange{
    connection: UdpConnection,
}

struct UnreliableExchange{
    
}
