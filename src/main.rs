use prism_relay::*;
use std::{path::Path, sync::Arc};
use tokio::net::TcpListener;
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!(
            "Relay operation failed; inspect configuration, permissions and connectivity. No payloads or credentials are logged."
        );
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: prism-relay serve|connect|bridge CONFIG_FILE".into());
    }
    let operation = async {
        match args[1].as_str() {
            "serve" => {
                let cfg: ServerSettings = read_settings(Path::new(&args[2]))?;
                let tls = server_tls(Path::new(&cfg.certificate), Path::new(&cfg.private_key))?;
                let relay = Relay::new(cfg.routes, Limits::default())?;
                let listener = TcpListener::bind(cfg.listen).await?;
                println!("listening {}", listener.local_addr()?);
                Arc::clone(&relay).serve(listener, tls).await
            }
            "connect" => connect_forever(read_settings(Path::new(&args[2]))?).await,
            "bridge" => {
                let cfg: PeerSettings = read_settings(Path::new(&args[2]))?;
                if !cfg.local.ip().is_loopback() {
                    return Err("bridge bind must be loopback".into());
                }
                let listener = TcpListener::bind(cfg.local).await?;
                println!("listening {}", listener.local_addr()?);
                bridge(cfg, listener).await
            }
            _ => Err("unknown command".into()),
        }
    };
    tokio::select! { result = operation => result, _ = tokio::signal::ctrl_c() => Ok(()) }
}
