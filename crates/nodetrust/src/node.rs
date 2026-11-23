//! Native libp2p node shared by all roles: TCP/DNS/WS(S) + noise + yamux, gossipsub discovery,
//! request/response over `libp2p-stream`. The swarm runs in its own task; [`Node`] is the handle.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, Transport,
    core::{multiaddr::Protocol, muxing::StreamMuxerBox, upgrade},
    dns, gossipsub, identify,
    identity::Keypair,
    noise, ping, relay,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle, dial_opts::DialOpts},
    tcp, upnp, websocket, yamux,
};
use tokio::sync::{mpsc, oneshot};

use crate::{discovery, wire, wss};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub stream: libp2p_stream::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub relay: Toggle<relay::Behaviour>,
    pub upnp: Toggle<upnp::tokio::Behaviour>,
}

#[derive(Default)]
pub struct NodeOptions {
    pub listen: Vec<Multiaddr>,
    /// serve as circuit relay (hop)
    pub relay: bool,
    /// UPnP port mapping
    pub upnp: bool,
    /// subscribe to the discovery topic (servers relay it, clients consume it)
    pub discovery: bool,
    /// dial peers learned via discovery
    pub dial_discovered: bool,
    /// served certificate for `/tls/ws` listen addresses
    pub wss_cert: Option<wss::CertHandle>,
    /// extra trust roots (DER) for dialing `/tls/ws`
    pub extra_roots: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum NodeEvent {
    Listening(Multiaddr),
    Discovered { peer: PeerId, addrs: Vec<Multiaddr> },
    Connected { peer: PeerId, addr: Multiaddr },
    Pong { peer: PeerId, rtt: Duration },
    ExternalPortMapped { local: Multiaddr, external: Multiaddr },
}

enum Command {
    Dial(Multiaddr, oneshot::Sender<anyhow::Result<PeerId>>),
    Listen(Multiaddr, oneshot::Sender<anyhow::Result<()>>),
    SetExternal(Vec<Multiaddr>),
    Announce,
}

/// Open connections per peer with their remote address (what the proof server attests).
pub type ConnAddrs = Arc<Mutex<HashMap<PeerId, HashMap<ConnectionId, Multiaddr>>>>;

#[derive(Clone)]
pub struct Node {
    pub peer_id: PeerId,
    pub control: libp2p_stream::Control,
    pub conn_addrs: ConnAddrs,
    cmd: mpsc::UnboundedSender<Command>,
}

/// Load a protobuf-encoded libp2p keypair, generating (and saving) an Ed25519 one if missing.
pub fn load_or_create_key(path: &Path) -> anyhow::Result<Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).with_context(|| format!("decoding key {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = Keypair::generate_ed25519();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, key.to_protobuf_encoding()?)?;
            tracing::info!(path = %path.display(), peer = %key.public().to_peer_id(), "generated identity");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading key {}", path.display())),
    }
}

/// Splits `/…/p2p/<id>` into the peer id and the address.
pub fn split_peer(addr: &Multiaddr) -> anyhow::Result<(PeerId, Multiaddr)> {
    let mut addr = addr.clone();
    match addr.pop() {
        Some(Protocol::P2p(peer)) => Ok((peer, addr)),
        _ => bail!("{addr} has no /p2p/<peer id> suffix"),
    }
}

/// IP of a plain TCP address (`/ip4|ip6/<ip>/tcp/<port>`), the only kind the proof server attests.
pub fn tcp_ip(addr: &Multiaddr) -> Option<IpAddr> {
    let mut it = addr.iter();
    let ip = match it.next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    matches!((it.next(), it.next()), (Some(Protocol::Tcp(_)), None)).then_some(ip)
}

impl Node {
    pub fn spawn(key: Keypair, opts: NodeOptions) -> anyhow::Result<(Node, mpsc::UnboundedReceiver<NodeEvent>)> {
        let peer_id = key.public().to_peer_id();
        let mut swarm = build_swarm(key, &opts)?;
        if opts.discovery {
            swarm.behaviour_mut().gossipsub.subscribe(&discovery::topic())?;
        }
        for addr in &opts.listen {
            swarm.listen_on(addr.clone()).with_context(|| format!("listen on {addr}"))?;
        }
        let control = swarm.behaviour().stream.new_control();
        let conn_addrs = ConnAddrs::default();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        tokio::spawn(run(swarm, opts.dial_discovered, conn_addrs.clone(), cmd_rx, ev_tx));
        Ok((Node { peer_id, control, conn_addrs, cmd: cmd_tx }, ev_rx))
    }

    /// Connect to `addr` (must end in `/p2p/<id>`) and return the peer id once connected.
    pub async fn dial(&self, addr: &Multiaddr) -> anyhow::Result<PeerId> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Command::Dial(addr.clone(), tx)).map_err(|_| anyhow!("node stopped"))?;
        tokio::time::timeout(REQUEST_TIMEOUT, rx).await.context("dial timed out")?.context("node stopped")?
    }

    pub async fn listen(&self, addr: Multiaddr) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Command::Listen(addr, tx)).map_err(|_| anyhow!("node stopped"))?;
        rx.await.context("node stopped")?
    }

    /// Replace our announced external addresses and announce them now.
    pub fn set_external(&self, addrs: Vec<Multiaddr>) {
        let _ = self.cmd.send(Command::SetExternal(addrs));
        let _ = self.cmd.send(Command::Announce);
    }

    pub fn announce(&self) {
        let _ = self.cmd.send(Command::Announce);
    }

    /// Dial `addr`, open `protocol` and run one request/response exchange.
    pub async fn request<Req, Resp>(&self, addr: &Multiaddr, protocol: StreamProtocol, req: &Req) -> anyhow::Result<Resp>
    where
        Req: prost::Message,
        Resp: prost::Message + Default,
    {
        let peer = self.dial(addr).await?;
        let fut = async {
            let mut stream = self.control.clone().open_stream(peer, protocol.clone()).await?;
            anyhow::Ok(wire::call(&mut stream, req).await?)
        };
        tokio::time::timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("{protocol} to {peer} timed out"))?
            .with_context(|| format!("{protocol} to {peer}"))
    }

    /// Serve `protocol`: `handler(peer, request)` is run per inbound stream on its own task.
    pub fn serve<Req, Resp, F, Fut>(&self, protocol: StreamProtocol, handler: F) -> anyhow::Result<()>
    where
        Req: prost::Message + Default + 'static,
        Resp: prost::Message + 'static,
        F: Fn(PeerId, Req) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
    {
        let mut incoming = self.control.clone().accept(protocol.clone()).map_err(|_| anyhow!("{protocol} already served"))?;
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            while let Some((peer, mut stream)) = incoming.next().await {
                let handler = handler.clone();
                let protocol = protocol.clone();
                tokio::spawn(async move {
                    let res = tokio::time::timeout(REQUEST_TIMEOUT * 10, async {
                        let req: Req = wire::read(&mut stream).await?;
                        let resp = handler(peer, req).await;
                        wire::write(&mut stream, &resp).await?;
                        futures::AsyncWriteExt::close(&mut stream).await
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::debug!(%peer, %protocol, "stream error: {e}"),
                        Err(_) => tracing::debug!(%peer, %protocol, "stream timed out"),
                    }
                });
            }
        });
        Ok(())
    }
}

fn build_swarm(key: Keypair, opts: &NodeOptions) -> anyhow::Result<Swarm<Behaviour>> {
    let mut tls = websocket::tls::Config::builder();
    for der in &opts.extra_roots {
        tls.add_trust(&websocket::tls::Certificate::new(der.clone()))?;
    }
    let tls = tls.finish();
    let relay_enabled = opts.relay;
    let upnp_enabled = opts.upnp;
    let wss_cert = opts.wss_cert.clone();
    let swarm = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_other_transport(move |key| -> Result<_, BoxError> {
            // order matters: the dns-wrapped TCP transport accepts any /dns address synchronously,
            // so the websocket transports must get the first look at an address.
            let mut ws = websocket::Config::new(dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp::Config::default()))?);
            ws.set_tls_config(tls);
            let plain = dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp::Config::default()))?;
            let mut t = secure(ws, key)?.or_transport(secure(plain, key)?).map(|e, _| e.into_inner()).boxed();
            if let Some(cert) = wss_cert {
                t = secure(wss::WssListener::new(cert)?, key)?.or_transport(t).map(|e, _| e.into_inner()).boxed();
            }
            Ok(t)
        })?
        .with_behaviour(|key| -> Result<_, BoxError> {
            Ok(Behaviour {
                stream: libp2p_stream::Behaviour::new(),
                gossipsub: discovery::gossipsub(key)?,
                identify: identify::Behaviour::new(identify::Config::new("/nodetrust/2.0.0".into(), key.public())),
                ping: ping::Behaviour::default(),
                relay: relay_enabled.then(|| relay::Behaviour::new(key.public().to_peer_id(), Default::default())).into(),
                upnp: upnp_enabled.then(upnp::tokio::Behaviour::default).into(),
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();
    Ok(swarm)
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

type Secured = libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)>;

/// noise + yamux on top of a raw transport.
fn secure<T>(t: T, key: &Keypair) -> anyhow::Result<Secured>
where
    T: Transport + Send + Unpin + 'static,
    T::Output: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
    T::Error: Send + Sync + 'static,
    T::Dial: Send + 'static,
    T::ListenerUpgrade: Send + 'static,
{
    Ok(t.upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed())
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    dial_discovered: bool,
    conn_addrs: ConnAddrs,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    ev_tx: mpsc::UnboundedSender<NodeEvent>,
) {
    let mut pending: HashMap<ConnectionId, oneshot::Sender<anyhow::Result<PeerId>>> = HashMap::new();
    let mut external: Vec<Multiaddr> = Vec::new();
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None => return,
                Some(Command::Dial(addr, tx)) => {
                    let Ok((peer, _)) = split_peer(&addr) else {
                        let _ = tx.send(Err(anyhow!("{addr} has no /p2p/<peer id> suffix")));
                        continue;
                    };
                    // reuse an existing connection to the same address
                    let existing = conn_addrs.lock().unwrap().get(&peer).is_some_and(|c| {
                        c.values().any(|a| addr.to_string().starts_with(&a.to_string()))
                    });
                    if existing {
                        let _ = tx.send(Ok(peer));
                        continue;
                    }
                    let opts = DialOpts::from(addr.clone());
                    let id = opts.connection_id();
                    match swarm.dial(opts) {
                        Ok(()) => { pending.insert(id, tx); }
                        Err(e) => { let _ = tx.send(Err(anyhow!("dial {addr}: {e}"))); }
                    }
                }
                Some(Command::Listen(addr, tx)) => {
                    let _ = tx.send(swarm.listen_on(addr.clone()).map(|_| ()).map_err(|e| anyhow!("listen on {addr}: {e}")));
                }
                Some(Command::SetExternal(addrs)) => {
                    for a in external.drain(..) {
                        swarm.remove_external_address(&a);
                    }
                    for a in &addrs {
                        swarm.add_external_address(a.clone());
                    }
                    external = addrs;
                }
                Some(Command::Announce) => {
                    if external.is_empty() { continue; }
                    let msg = discovery::encode(&external);
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(discovery::topic(), msg) {
                        tracing::debug!("announce: {e}");
                    }
                }
            },
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(%address, "listening");
                    let _ = ev_tx.send(NodeEvent::Listening(address));
                }
                SwarmEvent::ListenerError { error, .. } => tracing::warn!("listener error: {error}"),
                SwarmEvent::ListenerClosed { addresses, reason: Err(error), .. } => {
                    tracing::error!(?addresses, "listener closed: {error}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                    let addr = endpoint.get_remote_address().clone();
                    conn_addrs.lock().unwrap().entry(peer_id).or_default().insert(connection_id, addr.clone());
                    if let Some(tx) = pending.remove(&connection_id) {
                        let _ = tx.send(Ok(peer_id));
                    }
                    tracing::info!(peer = %peer_id, %addr, "connected");
                    let _ = ev_tx.send(NodeEvent::Connected { peer: peer_id, addr });
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, .. } => {
                    let mut map = conn_addrs.lock().unwrap();
                    if let Some(c) = map.get_mut(&peer_id) {
                        c.remove(&connection_id);
                        if c.is_empty() { map.remove(&peer_id); }
                    }
                }
                SwarmEvent::OutgoingConnectionError { connection_id, error, .. } => {
                    if let Some(tx) = pending.remove(&connection_id) {
                        let _ = tx.send(Err(anyhow!("{error}")));
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                    let Some(peer) = message.source else { continue };
                    let Some(addrs) = discovery::decode(&message.data) else {
                        tracing::debug!(%peer, "invalid announce");
                        continue;
                    };
                    if peer == *swarm.local_peer_id() { continue; }
                    let new = !swarm.is_connected(&peer);
                    tracing::info!(%peer, addrs = ?addrs, "discovered peer");
                    for a in &addrs {
                        swarm.add_peer_address(peer, a.clone());
                    }
                    if dial_discovered && new {
                        for a in &addrs {
                            let _ = swarm.dial(a.clone().with_p2p(peer).unwrap_or_else(|a| a));
                        }
                    }
                    let _ = ev_tx.send(NodeEvent::Discovered { peer, addrs });
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
                    let _ = ev_tx.send(NodeEvent::Pong { peer, rtt });
                }
                SwarmEvent::Behaviour(BehaviourEvent::Upnp(ev)) => match ev {
                    upnp::Event::NewExternalAddr { local_addr, external_addr } => {
                        tracing::info!(%local_addr, %external_addr, "upnp port mapped");
                        let _ = ev_tx.send(NodeEvent::ExternalPortMapped { local: local_addr, external: external_addr });
                    }
                    upnp::Event::GatewayNotFound => tracing::info!("upnp: no gateway found"),
                    upnp::Event::NonRoutableGateway => tracing::info!("upnp: gateway is not routable"),
                    ev => tracing::debug!(?ev, "upnp"),
                },
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    tracing::debug!(peer = %peer_id, agent = %info.agent_version, "identified");
                }
                _ => {}
            }
        }
    }
}
