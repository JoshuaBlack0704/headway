use aestunnel::Tunnel;
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
            rt.spawn(Tunnel::server());
            let t = rt.block_on(Tunnel::client(Url::parse("http://joshpc.com").unwrap())).unwrap();
            for x in 1..5{
                rt.block_on(t.send(vec![x, x*2, x*10]));
            }
            
        }
    }
}
