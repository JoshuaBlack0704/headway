use serde::{Deserialize, Serialize};
use strands::{common::addr, conn::Connection, server::UdpServer};
use tracing::{event, info_span, Level};

#[derive(Debug, Serialize, Deserialize)]
struct Obfus {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub v: Vec<u64>,
}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::init();

    let socket = UdpServer::new(addr(0, 0, 0, 0, 0)).await;
    let socket_addr = socket.get_local_addr();

    let client = tokio::task::spawn_blocking(move || {
        let span = info_span!("Client connect");
        let client = tokio::runtime::Handle::current().block_on(
            strands::conn::Connection::<Obfus>::connect_to("127.0.0.1", socket_addr.port()),
        );
        span.in_scope(|| {
            event!(Level::TRACE, "Client connected");
        });
        client
    });

    let mut conn = Connection::<Obfus>::next_conn(&socket).await;

    let mut client = client.await.unwrap();

    tokio::spawn(async move {
        let data = Obfus {
            a: 100,
            b: 1000,
            c: 2000,
            v: vec![100; 10000],
        };

        loop {
            client.send_reliable_encrypted(&data).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });

    loop {
        let hello: Obfus = conn.next_msg().await;
        let span = info_span!("Main Loop");
        let _event = span.entered();
        // event!(Level::INFO, "Server got {:?}", hello);
    }
}
