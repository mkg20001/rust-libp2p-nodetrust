// Pubsub discovery on _nodetrust_discovery_v2 (see crates/nodetrust/src/discovery.rs).
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromString } from '@libp2p/peer-id'
import { DISCOVERY_TOPIC, encode, decode } from './proto.js'

export const ANNOUNCE_INTERVAL = 10_000

export function encodeAnnounce (addrs) {
  return encode('Announce', { addr: addrs.map(a => multiaddr(a).bytes) })
}

/** @returns {string[] | null} addresses without trailing /p2p */
export function decodeAnnounce (data) {
  try {
    return decode('Announce', data).addr.map(b => {
      const s = multiaddr(b).toString()
      return s.replace(/\/p2p\/[^/]+$/, '')
    })
  } catch {
    return null
  }
}

const isSecureWs = a => a.includes('/tls/ws') || a.includes('/wss')

/**
 * Subscribe to discovery. `onPeer(peerId, addrs)` fires per announcement; if `dial` is set,
 * unconnected peers are dialed (`secureOnly` restricts that to WSS, as browsers require).
 * Returns { announce(addrs), stop() }.
 */
export function startDiscovery (libp2p, { onPeer = () => {}, dial = true, secureOnly = false, log = () => {} } = {}) {
  const pubsub = libp2p.services.pubsub
  pubsub.subscribe(DISCOVERY_TOPIC)
  let current = []

  const onMessage = (evt) => {
    const msg = evt.detail
    if (msg.topic !== DISCOVERY_TOPIC || msg.type !== 'signed') return
    const addrs = decodeAnnounce(msg.data)
    if (addrs == null) return log(`invalid announce from ${msg.from}`)
    const peer = msg.from.toString()
    if (peer === libp2p.peerId.toString()) return
    onPeer(peer, addrs)
    if (!dial || libp2p.getConnections(peerIdFromString(peer)).length > 0) return
    for (const a of addrs.filter(a => !secureOnly || isSecureWs(a))) {
      libp2p.dial(multiaddr(`${a}/p2p/${peer}`)).catch(err => log(`dial ${a}: ${err.message}`))
    }
  }
  pubsub.addEventListener('message', onMessage)

  const publish = () => {
    if (current.length === 0) return
    pubsub.publish(DISCOVERY_TOPIC, encodeAnnounce(current)).catch(err => log(`announce: ${err.message}`))
  }
  const timer = setInterval(publish, ANNOUNCE_INTERVAL)

  return {
    announce (addrs) {
      current = addrs
      publish()
    },
    stop () {
      clearInterval(timer)
      pubsub.removeEventListener('message', onMessage)
      pubsub.unsubscribe(DISCOVERY_TOPIC)
    }
  }
}
