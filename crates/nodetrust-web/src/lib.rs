//! Browser client (wasm32): dial the issue server, join pubsub discovery, dial announced WSS
//! peers. Same interface as the JS client's browser mode: `start(issuer, onPeer, onConnect)`.

use std::time::Duration;

use futures::{StreamExt, channel::mpsc};
use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{muxing::StreamMuxerBox, upgrade},
    gossipsub, identify, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    websocket_websys, yamux,
};
use nodetrust::discovery;
use wasm_bindgen::prelude::*;

use behaviour::{Behaviour, BehaviourEvent};
mod behaviour {
    // the derive's generated code trips this lint on current rustc
    #![allow(unreachable_code)]
    use super::*;

    #[derive(NetworkBehaviour)]
    pub struct Behaviour {
        pub gossipsub: gossipsub::Behaviour,
        pub identify: identify::Behaviour,
        pub ping: ping::Behaviour,
    }
}

/// Handle to a running node; `stop()` shuts it down.
#[wasm_bindgen]
pub struct NodetrustNode {
    peer_id: String,
    stop: mpsc::UnboundedSender<()>,
}

#[wasm_bindgen]
impl NodetrustNode {
    #[wasm_bindgen(getter, js_name = peerId)]
    pub fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    pub fn stop(&self) {
        let _ = self.stop.unbounded_send(());
    }
}

/// Start a node. `on_peer(peerId, addrs[])` fires for every announcement, `on_connect(peerId, addr)`
/// for every established connection (issuer included).
#[wasm_bindgen]
pub fn start(issuer: &str, on_peer: js_sys::Function, on_connect: js_sys::Function) -> Result<NodetrustNode, JsError> {
    let issuer: Multiaddr = issuer.parse().map_err(|e| JsError::new(&format!("issuer address: {e}")))?;
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_wasm_bindgen()
        .with_other_transport(|key| {
            Ok(websocket_websys::Transport::default()
                .upgrade(upgrade::Version::V1Lazy)
                .authenticate(noise::Config::new(key)?)
                .multiplex(yamux::Config::default())
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer))))
        })
        .map_err(|e| JsError::new(&e.to_string()))?
        .with_behaviour(|key| {
            Ok(Behaviour {
                gossipsub: discovery::gossipsub(key)?,
                identify: identify::Behaviour::new(identify::Config::new("/nodetrust/2.0.0".into(), key.public())),
                ping: ping::Behaviour::default(),
            })
        })
        .map_err(|e| JsError::new(&e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();
    swarm.behaviour_mut().gossipsub.subscribe(&discovery::topic()).map_err(|e| JsError::new(&e.to_string()))?;
    swarm.dial(issuer).map_err(|e| JsError::new(&e.to_string()))?;

    let peer_id = swarm.local_peer_id().to_string();
    let (stop, mut stopped) = mpsc::unbounded();
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            futures::select! {
                _ = stopped.next() => break,
                ev = swarm.select_next_some() => match ev {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        call(&on_connect, &peer_id, &[JsValue::from_str(&endpoint.get_remote_address().to_string())]);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let (Some(peer), Some(addrs)) = (message.source, discovery::decode(&message.data)) else { continue };
                        let js_addrs: js_sys::Array = addrs.iter().map(|a| JsValue::from_str(&a.to_string())).collect();
                        call(&on_peer, &peer, &[js_addrs.into()]);
                        if !swarm.is_connected(&peer) {
                            // browsers can only dial secure websockets
                            for a in addrs.into_iter().filter(|a| a.to_string().contains("/tls/ws") || a.to_string().contains("/wss")) {
                                let _ = swarm.dial(a.with_p2p(peer).unwrap_or_else(|a| a));
                            }
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        web_sys_log(&format!("dial {peer_id:?} failed: {error}"));
                    }
                    _ => {}
                }
            }
        }
    });
    Ok(NodetrustNode { peer_id, stop })
}

fn call(f: &js_sys::Function, peer: &PeerId, rest: &[JsValue]) {
    let args: js_sys::Array =
        std::iter::once(JsValue::from_str(&peer.to_string())).chain(rest.iter().cloned()).collect();
    if let Err(e) = f.apply(&JsValue::NULL, &args) {
        web_sys_log(&format!("callback threw: {e:?}"));
    }
}

fn web_sys_log(msg: &str) {
    web_sys::console::warn_1(&msg.into());
}
