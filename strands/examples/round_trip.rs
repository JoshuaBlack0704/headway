use log::info;
use strands::{server::UdpServer, common::addr};

#[tokio::main]
pub async fn main(){
    pretty_env_logger::init();
    let srv = UdpServer::new(addr(0,0,0,0,0)).await;
    info!("Server addr: {}", srv.get_local_addr());
    let client = UdpServer::new(addr(0,0,0,0,0)).await;
    info!("Client addr: {}", client.get_local_addr());
}
