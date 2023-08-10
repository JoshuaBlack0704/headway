use log::info;
use strands::{server::UdpServer, common::addr};

#[tokio::main]
pub async fn main(){
    pretty_env_logger::init();
    let srv = UdpServer::new(addr(0,0,0,0,0)).await;
    info!("Server addr: {}", srv.get_local_addr());
    let client = UdpServer::new(addr(0,0,0,0,0)).await;
    info!("Client addr: {}", client.get_local_addr());

    let data = [10u8;100];
    client.send_to(addr(127, 0, 0, 1, srv.get_local_addr().port()), &data).await;

    let peer = srv.next_peer().await;
    info!("Srv got peer {}", peer.0);
    let msg = peer.1.recv_async().await.unwrap();
    info!("Srv got {:?} from {}", msg, peer.0);
}
