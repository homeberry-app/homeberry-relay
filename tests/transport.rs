use prism_relay::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn route() -> RouteConfig {
    RouteConfig {
        id: hex(&[1; 32]),
        hub_token_sha256: hex(&token_hash(&[2; 32])),
        client_token_sha256: hex(&token_hash(&[3; 32])),
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    hub: PeerSettings,
    client: PeerSettings,
    tls: Arc<rustls::ClientConfig>,
    server: tokio::task::JoinHandle<()>,
    echo: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        self.echo.abort();
    }
}
async fn fixture(limits: Limits) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let tls = client_tls(Some(cert_path.to_str().unwrap())).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = listener.local_addr().unwrap().to_string();
    let relay_service = Relay::new(
        vec![
            route(),
            RouteConfig {
                id: hex(&[4; 32]),
                hub_token_sha256: hex(&token_hash(&[5; 32])),
                client_token_sha256: hex(&token_hash(&[6; 32])),
            },
        ],
        limits,
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let _ = relay_service
            .serve(listener, server_tls(&cert_path, &key_path).unwrap())
            .await;
    });
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let (socket, _) = target.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = socket.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let hub = PeerSettings {
        relay,
        server_name: "localhost".into(),
        ca_certificate: Some(dir.path().join("cert.pem").display().to_string()),
        route: hex(&[1; 32]),
        token: hex(&[2; 32]),
        local,
    };
    let mut client = hub.clone();
    client.token = hex(&[3; 32]);
    Fixture {
        _dir: dir,
        hub,
        client,
        tls,
        server,
        echo,
    }
}
async fn registered(f: &Fixture) -> tokio_rustls::client::TlsStream<TcpStream> {
    open(&f.hub, HUB, f.tls.clone()).await.unwrap()
}
async fn exchange(f: &Fixture, message: &[u8]) {
    let mut hub = registered(f).await;
    let client_settings = f.client.clone();
    let tls = f.tls.clone();
    let message = message.to_vec();
    let client = tokio::spawn(async move {
        let mut peer = open(&client_settings, CLIENT, tls).await.unwrap();
        peer.write_all(&message).await.unwrap();
        let mut reply = vec![0; message.len()];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, message);
    });
    assert_eq!(hub.read_u8().await.unwrap(), MATCHED);
    hub.write_u8(READY).await.unwrap();
    let mut bytes = [0; 3];
    hub.read_exact(&mut bytes).await.unwrap();
    hub.write_all(&bytes).await.unwrap();
    client.await.unwrap();
}
#[tokio::test]
async fn authenticated_opaque_exchange_and_reconnect() {
    let f = fixture(Limits::default()).await;
    exchange(&f, b"abc").await;
    exchange(&f, b"xyz").await;
}
#[tokio::test]
async fn unauthorized_role_unknown_route_and_wrong_hostname_rejected() {
    let f = fixture(Limits::default()).await;
    assert!(open(&f.client, HUB, f.tls.clone()).await.is_err());
    let mut wrong = f.client.clone();
    wrong.token = hex(&[9; 32]);
    assert!(open(&wrong, CLIENT, f.tls.clone()).await.is_err());
    wrong = f.client.clone();
    wrong.route = hex(&[9; 32]);
    assert!(open(&wrong, CLIENT, f.tls.clone()).await.is_err());
    wrong = f.hub.clone();
    wrong.server_name = "wrong.example".into();
    assert!(open(&wrong, HUB, f.tls.clone()).await.is_err());
    assert!(open(&f.hub, HUB, client_tls(None).unwrap()).await.is_err());
}
#[tokio::test]
async fn disconnected_hub_and_expired_slot_do_not_block_new_connections() {
    let f = fixture(Limits {
        waiting: Duration::from_millis(100),
        per_route: 1,
        ..Limits::default()
    })
    .await;
    let hub = registered(&f).await;
    drop(hub);
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mut second = registered(&f).await;
    assert!(open(&f.hub, HUB, f.tls.clone()).await.is_err());
    assert!(second.read_u8().await.is_err());
    assert!(open(&f.client, CLIENT, f.tls.clone()).await.is_err());
    exchange(&f, b"abc").await;
}
#[tokio::test]
async fn partial_preface_releases_global_slot() {
    let f = fixture(Limits {
        handshake: Duration::from_millis(100),
        connections: 1,
        ..Limits::default()
    })
    .await;
    let socket = TcpStream::connect(&f.hub.relay).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(f.tls.clone())
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await
        .unwrap();
    tls.write_all(b"PRLY").await.unwrap();
    assert!(tls.read_u8().await.is_err());
    let _ = registered(&f).await;
}
#[tokio::test]
async fn forwarding_caps_idle_bytes_and_backpressure() {
    let (mut a, mut left) = tokio::io::duplex(32);
    let (mut b, mut right) = tokio::io::duplex(32);
    let limits = Limits {
        idle: Duration::from_millis(50),
        lifetime: Duration::from_secs(1),
        bytes_per_direction: 4,
        ..Limits::default()
    };
    let task = tokio::spawn(async move { forward(&mut a, &mut b, &limits).await });
    left.write_all(b"12345").await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(right.read(&mut [0; 8]).await.unwrap(), 0);
    let (mut a, _left) = tokio::io::duplex(32);
    let (mut b, _right) = tokio::io::duplex(32);
    assert!(
        forward(
            &mut a,
            &mut b,
            &Limits {
                idle: Duration::from_millis(30),
                ..Limits::default()
            }
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn outbound_connector_forwards_only_configured_loopback_target() {
    let f = fixture(Limits::default()).await;
    let hub = f.hub.clone();
    let tls = f.tls.clone();
    let connector = tokio::spawn(async move { connect_once(&hub, tls).await });
    let mut client = None;
    for _ in 0..20 {
        if let Ok(peer) = open(&f.client, CLIENT, f.tls.clone()).await {
            client = Some(peer);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut client = client.unwrap();
    client.write_all(b"opaque payload").await.unwrap();
    let mut reply = [0; 14];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"opaque payload");
    connector.abort();
    let mut bad = f.hub.clone();
    bad.local = "192.0.2.1:443".parse().unwrap();
    assert!(connect_once(&bad, f.tls.clone()).await.is_err());
}
#[test]
fn rejects_invalid_configuration_and_role_credential_reuse() {
    assert!(hex32("ABC").is_err());
    let mut r = route();
    r.client_token_sha256 = r.hub_token_sha256.clone();
    assert!(Relay::new(vec![r], Limits::default()).is_err());
    assert!(Relay::new(vec![route(), route()], Limits::default()).is_err());
    assert!(Relay::new(vec![], Limits::default()).is_err());
}

#[tokio::test]
async fn valid_credentials_cannot_attach_to_another_household_route() {
    let f = fixture(Limits::default()).await;
    let mut hub = registered(&f).await;
    let mut other = f.client.clone();
    other.route = hex(&[4; 32]);
    other.token = hex(&[6; 32]);
    assert!(open(&other, CLIENT, f.tls.clone()).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), hub.read_u8())
            .await
            .is_err()
    );
    drop(hub);
    tokio::time::sleep(Duration::from_millis(30)).await;
    exchange(&f, b"abc").await;
}
#[tokio::test]
async fn stalled_receiver_is_bounded_and_shutdown_cleans_up() {
    let (mut a, mut left) = tokio::io::duplex(32);
    let (mut b, _right) = tokio::io::duplex(32);
    let limits = Limits {
        idle: Duration::from_millis(50),
        lifetime: Duration::from_secs(1),
        ..Limits::default()
    };
    let task = tokio::spawn(async move { forward(&mut a, &mut b, &limits).await });
    assert!(left.write_all(&vec![0u8; 1024 * 1024]).await.is_err());
    assert!(task.await.unwrap().is_err());
}
#[tokio::test]
async fn restart_with_rotated_client_credential_rejects_old_access() {
    let mut f = fixture(Limits::default()).await;
    f.server.abort();
    let _ = (&mut f.server).await;
    let listener = TcpListener::bind(&f.hub.relay).await.unwrap();
    let mut replacement = route();
    replacement.client_token_sha256 = hex(&token_hash(&[9; 32]));
    let relay = Relay::new(vec![replacement], Limits::default()).unwrap();
    let tls = server_tls(
        &f._dir.path().join("cert.pem"),
        &f._dir.path().join("key.pem"),
    )
    .unwrap();
    f.server = tokio::spawn(async move {
        let _ = relay.serve(listener, tls).await;
    });
    assert!(open(&f.client, CLIENT, f.tls.clone()).await.is_err());
    f.client.token = hex(&[9; 32]);
    exchange(&f, b"abc").await;
}
