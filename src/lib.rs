use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const MAGIC: &[u8; 8] = b"PRLY0001";
pub const HUB: u8 = 1;
pub const CLIENT: u8 = 2;
pub const READY: u8 = 1;
pub const MATCHED: u8 = 2;
pub const UNAVAILABLE: u8 = 3;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}

pub fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(fail("expected 32-byte lowercase hex value").into());
    }
    let mut bytes = [0; 32];
    for (n, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[n * 2..n * 2 + 2], 16)?;
    }
    Ok(bytes)
}
pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub id: String,
    pub hub_token_sha256: String,
    pub client_token_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub listen: SocketAddr,
    pub certificate: String,
    pub private_key: String,
    pub routes: Vec<RouteConfig>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSettings {
    pub relay: String,
    pub server_name: String,
    pub ca_certificate: Option<String>,
    pub route: String,
    pub token: String,
    pub local: SocketAddr,
}
pub fn read_settings<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 65536 {
        return Err(fail("configuration must be a regular file under 64 KiB").into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(fail("configuration must have mode 0600").into());
        }
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
pub fn server_tls(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| fail("missing TLS key"))?;
    Ok(Arc::new(
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}
pub fn client_tls(ca: Option<&str>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca {
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        {
            roots.add(cert?)?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[derive(Clone)]
pub struct Limits {
    pub handshake: Duration,
    pub waiting: Duration,
    pub idle: Duration,
    pub lifetime: Duration,
    pub connections: usize,
    pub per_route: usize,
    pub bytes_per_direction: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            waiting: Duration::from_secs(30),
            idle: Duration::from_secs(60),
            lifetime: Duration::from_secs(600),
            connections: 128,
            per_route: 8,
            bytes_per_direction: 128 * 1024 * 1024,
        }
    }
}
struct Peer {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    _slot: OwnedSemaphorePermit,
}
struct Route {
    hub_hash: [u8; 32],
    client_hash: [u8; 32],
    slots: Arc<Semaphore>,
    waiting: Mutex<VecDeque<oneshot::Sender<Peer>>>,
}
pub struct Relay {
    routes: HashMap<[u8; 32], Arc<Route>>,
    slots: Arc<Semaphore>,
    limits: Limits,
}
impl Relay {
    pub fn new(routes: Vec<RouteConfig>, limits: Limits) -> Result<Arc<Self>> {
        if routes.is_empty()
            || routes.len() > 64
            || limits.connections == 0
            || limits.per_route == 0
            || limits.bytes_per_direction == 0
        {
            return Err(fail("invalid relay bounds").into());
        }
        let mut entries = HashMap::new();
        for c in routes {
            let route = Route {
                hub_hash: hex32(&c.hub_token_sha256)?,
                client_hash: hex32(&c.client_token_sha256)?,
                slots: Arc::new(Semaphore::new(limits.per_route)),
                waiting: Mutex::new(VecDeque::new()),
            };
            if route.hub_hash == route.client_hash
                || entries.insert(hex32(&c.id)?, Arc::new(route)).is_some()
            {
                return Err(fail("duplicate route or shared role credential").into());
            }
        }
        Ok(Arc::new(Self {
            routes: entries,
            slots: Arc::new(Semaphore::new(limits.connections)),
            limits,
        }))
    }
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        tls: Arc<ServerConfig>,
    ) -> Result<()> {
        let acceptor = TlsAcceptor::from(tls);
        let mut jobs = JoinSet::new();
        let mut window = Instant::now();
        let mut admitted = 0;
        loop {
            tokio::select! {
                item = listener.accept() => {
                    let (socket, _) = item?;
                    if window.elapsed() >= Duration::from_secs(1) { window = Instant::now(); admitted = 0; }
                    // Bound TLS work as well as active sockets. No unbounded per-IP map.
                    if admitted >= 64 { drop(socket); continue; }
                    let Ok(slot) = self.slots.clone().try_acquire_owned() else { drop(socket); continue; };
                    admitted += 1;
                    let relay = self.clone(); let acceptor = acceptor.clone();
                    jobs.spawn(async move {
                        // Errors intentionally do not log addresses, routes, credentials or payloads.
                        let _ = relay.accept(socket, slot, acceptor).await;
                    });
                }
                _ = jobs.join_next(), if !jobs.is_empty() => {}
            }
        }
    }
    async fn accept(
        &self,
        socket: TcpStream,
        slot: OwnedSemaphorePermit,
        acceptor: TlsAcceptor,
    ) -> Result<()> {
        let mut stream =
            tokio::time::timeout(self.limits.handshake, acceptor.accept(socket)).await??;
        let mut header = [0u8; 73];
        tokio::time::timeout(self.limits.handshake, stream.read_exact(&mut header)).await??;
        if &header[..8] != MAGIC || ![HUB, CLIENT].contains(&header[8]) {
            return Err(fail("invalid preface").into());
        }
        let id: [u8; 32] = header[9..41].try_into()?;
        let token: [u8; 32] = header[41..].try_into()?;
        let hash = token_hash(&token);
        let Some(route) = self.routes.get(&id).cloned() else {
            return Err(fail("unauthorized").into());
        };
        let expected = if header[8] == HUB {
            route.hub_hash
        } else {
            route.client_hash
        };
        if !bool::from(hash.ct_eq(&expected)) {
            return Err(fail("unauthorized").into());
        }
        if header[8] == CLIENT {
            let sender = {
                let mut waiting = route.waiting.lock().unwrap();
                waiting.retain(|s| !s.is_closed());
                waiting.pop_front()
            };
            if let Some(sender) = sender {
                let _ = sender.send(Peer {
                    stream,
                    _slot: slot,
                });
                return Ok(());
            }
            tokio::time::timeout(self.limits.handshake, stream.write_u8(UNAVAILABLE)).await??;
            return Ok(());
        }
        let _route_slot = route
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| fail("route full"))?;
        tokio::time::timeout(self.limits.handshake, stream.write_u8(READY)).await??;
        let (sender, receiver) = oneshot::channel();
        {
            let mut waiting = route.waiting.lock().unwrap();
            waiting.retain(|s| !s.is_closed());
            waiting.push_back(sender);
        }
        let peer = tokio::select! {
            peer = tokio::time::timeout(self.limits.waiting, receiver) => peer??,
            _ = stream.read_u8() => return Err(fail("waiting connector closed or sent early data").into()),
        };
        let Peer {
            stream: mut client,
            _slot: _client_slot,
        } = peer;
        tokio::time::timeout(self.limits.handshake, async {
            stream.write_u8(MATCHED).await?;
            if stream.read_u8().await? != READY {
                return Err(fail("connector target unavailable"));
            }
            client.write_u8(READY).await
        })
        .await??;
        forward(&mut stream, &mut client, &self.limits).await
    }
}

/// Fixed-size buffers with aggregate activity timeout and a total byte/lifetime cap.
/// No framing interpretation or payload persistence after rendezvous.
pub async fn forward<A, B>(a: &mut A, b: &mut B, limits: &Limits) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        mut r: R,
        mut w: W,
        activity: watch::Sender<Instant>,
        max: u64,
    ) -> Result<()> {
        let mut buffer = [0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut buffer).await?;
            if n == 0 {
                w.shutdown().await?;
                return Ok(());
            }
            total += n as u64;
            if total > max {
                return Err(fail("stream byte limit").into());
            }
            activity.send_replace(Instant::now());
            w.write_all(&buffer[..n]).await?;
            activity.send_replace(Instant::now());
        }
    }
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let (activity, mut updates) = watch::channel(Instant::now());
    let copying = async {
        tokio::try_join!(
            pump(ar, bw, activity.clone(), limits.bytes_per_direction),
            pump(br, aw, activity.clone(), limits.bytes_per_direction)
        )?;
        Ok(())
    };
    let idle = async {
        loop {
            tokio::time::timeout(limits.idle, updates.changed())
                .await
                .map_err(|_| fail("stream idle timeout"))?
                .map_err(|_| fail("stream closed"))?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    tokio::select! {
        result = copying => result,
        result = idle => { result?; Ok(()) },
        _ = tokio::time::sleep(limits.lifetime) => Err(fail("stream lifetime limit").into()),
    }
}

pub async fn open(
    settings: &PeerSettings,
    role: u8,
    tls: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let name = ServerName::try_from(settings.server_name.clone())?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(&settings.relay).await?;
        let mut stream = TlsConnector::from(tls).connect(name, socket).await?;
        let mut header = Vec::with_capacity(73);
        header.extend_from_slice(MAGIC);
        header.push(role);
        header.extend_from_slice(&hex32(&settings.route)?);
        header.extend_from_slice(&hex32(&settings.token)?);
        stream.write_all(&header).await?;
        if stream.read_u8().await? != READY {
            return Err(fail("relay not ready").into());
        }
        Ok(stream)
    })
    .await?
}
pub async fn connect_once(settings: &PeerSettings, tls: Arc<ClientConfig>) -> Result<()> {
    connect_attempt(settings, tls, &std::sync::atomic::AtomicBool::new(false)).await
}
async fn connect_attempt(
    settings: &PeerSettings,
    tls: Arc<ClientConfig>,
    matched: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    if !settings.local.ip().is_loopback() {
        return Err(fail("connector target must be loopback").into());
    }
    let mut stream = open(settings, HUB, tls).await?;
    if tokio::time::timeout(Duration::from_secs(35), stream.read_u8()).await?? != MATCHED {
        return Err(fail("invalid match").into());
    }
    let mut target =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(settings.local)).await??;
    stream.write_u8(READY).await?;
    matched.store(true, std::sync::atomic::Ordering::Relaxed);
    forward(&mut stream, &mut target, &Limits::default()).await
}
pub async fn connect_forever(settings: PeerSettings) -> Result<()> {
    if !settings.local.ip().is_loopback() {
        return Err(fail("connector target must be loopback").into());
    }
    hex32(&settings.route)?;
    hex32(&settings.token)?;
    let tls = client_tls(settings.ca_certificate.as_deref())?;
    let mut workers = JoinSet::new();
    for worker in 0..4 {
        let settings = settings.clone();
        let tls = tls.clone();
        workers.spawn(async move {
            let mut backoff = 1;
            loop {
                let started = Instant::now();
                let matched = std::sync::atomic::AtomicBool::new(false);
                let _ = connect_attempt(&settings, tls.clone(), &matched).await;
                if matched.load(std::sync::atomic::Ordering::Relaxed) {
                    backoff = 1;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    backoff = 1;
                }
                let jitter = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_millis() as u64
                    % 250;
                tokio::time::sleep(Duration::from_millis(
                    backoff * 1000 + worker * 125 + jitter,
                ))
                .await;
                backoff = (backoff * 2).min(30);
            }
        });
    }
    workers.join_next().await;
    Err(fail("connector worker stopped").into())
}
pub async fn bridge(settings: PeerSettings, listener: TcpListener) -> Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(fail("client bridge must be loopback").into());
    }
    let tls = client_tls(settings.ca_certificate.as_deref())?;
    let slots = Arc::new(Semaphore::new(8));
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut local, _) = result?;
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let settings = settings.clone(); let tls = tls.clone();
                jobs.spawn(async move { let _slot = slot; if let Ok(mut remote) = open(&settings, CLIENT, tls).await { let _ = forward(&mut local, &mut remote, &Limits::default()).await; } });
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {}
        }
    }
}
