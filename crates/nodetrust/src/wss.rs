//! WSS listener whose certificate can be swapped at runtime.
//!
//! `libp2p-websocket` fixes its server TLS config when the transport is built, so for listening
//! we terminate TLS one layer below it (TCP → rustls with a swappable resolver → websocket) and
//! translate `/tls/ws` ⇄ `/ws` addresses so the swarm sees what is really served.
//! Dialing is left to the regular websocket transport (this one refuses dials).

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use arc_swap::ArcSwapOption;
use futures::future::Either;
use libp2p::{
    Multiaddr, Transport,
    core::{
        multiaddr::Protocol,
        transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    },
    tcp, websocket,
};
use rustls::{
    ServerConfig,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

/// Shared handle to the certificate currently served. Empty until the first `set`.
#[derive(Clone, Debug, Default)]
pub struct CertHandle(Arc<ArcSwapOption<CertifiedKey>>);

impl CertHandle {
    /// Replace the served certificate (PEM chain + PEM private key). Takes effect for new handshakes.
    pub fn set(&self, chain_pem: &str, key_pem: &str) -> anyhow::Result<()> {
        let chain = rustls_pemfile::certs(&mut chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
        let provider = rustls::crypto::ring::default_provider();
        let ck = CertifiedKey::from_der(chain, key, &provider)?;
        self.0.store(Some(Arc::new(ck)));
        Ok(())
    }
}

impl ResolvesServerCert for CertHandle {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_full()
    }
}

/// Listen-only `/tls/ws` transport backed by [`CertHandle`].
pub struct WssListener {
    inner: websocket::Config<TlsTcpTransport>,
}

impl WssListener {
    pub fn new(cert: CertHandle) -> anyhow::Result<Self> {
        let cfg = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert));
        let acceptor = futures_rustls::TlsAcceptor::from(Arc::new(cfg));
        let tls_tcp = TlsTcpTransport { tcp: tcp::tokio::Transport::new(tcp::Config::default()), acceptor };
        Ok(Self { inner: websocket::Config::new(tls_tcp) })
    }
}

/// `/tls/ws` → `/ws` (what the inner websocket transport serves), `None` if not a wss address.
fn strip_tls(addr: &Multiaddr) -> Option<Multiaddr> {
    let mut out = Multiaddr::empty();
    let mut iter = addr.iter().peekable();
    let mut seen = false;
    while let Some(p) = iter.next() {
        match p {
            Protocol::Tls if matches!(iter.peek(), Some(Protocol::Ws(_))) => seen = true,
            Protocol::Wss(path) => {
                seen = true;
                out.push(Protocol::Ws(path));
            }
            p => out.push(p),
        }
    }
    seen.then_some(out)
}

/// `/ws` → `/tls/ws`
fn add_tls(addr: Multiaddr) -> Multiaddr {
    addr.iter()
        .flat_map(|p| match p {
            Protocol::Ws(path) => Either::Left([Protocol::Tls, Protocol::Ws(path)].into_iter()),
            p => Either::Right(std::iter::once(p)),
        })
        .collect()
}

impl Transport for WssListener {
    type Output = <websocket::Config<TlsTcpTransport> as Transport>::Output;
    type Error = <websocket::Config<TlsTcpTransport> as Transport>::Error;
    type ListenerUpgrade = <websocket::Config<TlsTcpTransport> as Transport>::ListenerUpgrade;
    type Dial = <websocket::Config<TlsTcpTransport> as Transport>::Dial;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        let inner = strip_tls(&addr).ok_or(TransportError::MultiaddrNotSupported(addr))?;
        self.inner.listen_on(id, inner)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr, _: DialOpts) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx).map(|ev| match ev {
            TransportEvent::NewAddress { listener_id, listen_addr } => {
                TransportEvent::NewAddress { listener_id, listen_addr: add_tls(listen_addr) }
            }
            TransportEvent::AddressExpired { listener_id, listen_addr } => {
                TransportEvent::AddressExpired { listener_id, listen_addr: add_tls(listen_addr) }
            }
            TransportEvent::Incoming { listener_id, upgrade, local_addr, send_back_addr } => TransportEvent::Incoming {
                listener_id,
                upgrade,
                local_addr: add_tls(local_addr),
                send_back_addr,
            },
            ev => ev,
        })
    }
}

/// TCP with a TLS accept on every inbound connection.
struct TlsTcpTransport {
    tcp: tcp::tokio::Transport,
    acceptor: futures_rustls::TlsAcceptor,
}

type TlsFut = Pin<Box<dyn Future<Output = std::io::Result<futures_rustls::server::TlsStream<tcp::tokio::TcpStream>>> + Send>>;

impl Transport for TlsTcpTransport {
    type Output = futures_rustls::server::TlsStream<tcp::tokio::TcpStream>;
    type Error = std::io::Error;
    type ListenerUpgrade = TlsFut;
    type Dial = TlsFut;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        self.tcp.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.tcp.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr, _: DialOpts) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let acceptor = self.acceptor.clone();
        Pin::new(&mut self.tcp).poll(cx).map(|ev| {
            ev.map_upgrade(move |upgrade| {
                Box::pin(async move { acceptor.accept(upgrade.await?).await }) as TlsFut
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_rewrite() {
        let wss: Multiaddr = "/ip4/0.0.0.0/tcp/4443/tls/ws".parse().unwrap();
        let ws: Multiaddr = "/ip4/0.0.0.0/tcp/4443/ws".parse().unwrap();
        assert_eq!(strip_tls(&wss), Some(ws.clone()));
        assert_eq!(strip_tls(&"/ip4/0.0.0.0/tcp/4443/wss".parse().unwrap()), Some(ws.clone()));
        assert_eq!(strip_tls(&ws), None);
        assert_eq!(add_tls(ws), wss);
    }
}
