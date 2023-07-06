use aestunnel::{Tunnel, TUNNEL_SERVER_PORT};
use tokio::runtime;
use url::Url;

fn main(){
    pretty_env_logger::init();
    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Could not create tokio runtime");
    {
        {
            rt.spawn(Tunnel::server(("0.0.0.0", TUNNEL_SERVER_PORT)));
            let t = rt.block_on(Tunnel::client(Url::parse("http://localhost").unwrap())).unwrap();
            for x in 1..5{
                rt.block_on(t.send(vec![x, x*2, x*10]));
            }
            
        }
    }
}
