// libp2p-nodetrust js client.
//
// Node: `startClient()` obtains a certificate, hands it to @libp2p/websockets (which then serves
// https on its /ws listener), announces /dns4|dns6/…/tls/ws addresses and renews in place.
// Browser: `startDiscovery()` joins discovery and dials announced WSS peers.
import { multiaddr } from '@multiformats/multiaddr'
import { obtain } from './client.js'
import { startDiscovery } from './discovery.js'
import { parseIpLabel } from './names.js'
import { renewDue } from './tlskey.js'
import { createStore } from './store.js'

export * from './proto.js'
export * from './names.js'
export { obtain } from './client.js'
export { startDiscovery, encodeAnnounce, decodeAnnounce, ANNOUNCE_INTERVAL } from './discovery.js'
export { CRYPTO_NAMES, renewDue } from './tlskey.js'
export { createStore } from './store.js'

/**
 * Service that feeds certificates to the websockets transport (it listens for
 * `certificate:provision` / `certificate:renew` on the internal event bus).
 * Add as `services: { nodetrustTls: nodetrustTls() }`.
 */
export function nodetrustTls () {
  return (components) => ({
    [Symbol.toStringTag]: 'nodetrustTls',
    provision (detail) { components.events.safeDispatchEvent('certificate:provision', { detail }) },
    renew (detail) { components.events.safeDispatchEvent('certificate:renew', { detail }) }
  })
}

/** /dns4|dns6/<name>/tcp/<port>/tls/ws for every ip name of the certificate */
export function externalAddrs (altnames, ports) {
  return altnames.flatMap(name => {
    const ip = parseIpLabel(name.split('.')[0])
    if (ip == null) return []
    const v6 = ip.includes(':')
    const port = v6 ? ports.v6 : ports.v4
    return port == null ? [] : [`/${v6 ? 'dns6' : 'dns4'}/${name}/tcp/${port}/tls/ws`]
  })
}

function wsPorts (libp2p) {
  const ports = {}
  for (const ma of libp2p.getMultiaddrs()) {
    const s = ma.toString()
    const m = s.match(/^\/(ip4|ip6)\/[^/]+\/tcp\/(\d+)\/(tls\/)?ws/)
    if (m != null) ports[m[1] === 'ip4' ? 'v4' : 'v6'] ??= Number(m[2])
  }
  return ports
}

/**
 * Full client (Node). libp2p needs tcp + websockets (listening on a /ws address), gossipsub as
 * `pubsub` and `nodetrustTls`.
 */
export async function startClient (libp2p, { issuer, stateDir, cryptos, dial = true, log = console.log }) {
  const store = createStore(stateDir)
  const tls = libp2p.services.nodetrustTls
  const discovery = startDiscovery(libp2p, {
    dial,
    log,
    onPeer: (peer, addrs) => log(`discovered peer ${peer} ${addrs.join(' ')}`)
  })
  libp2p.addEventListener('connection:open', evt => {
    log(`connected ${evt.detail.remotePeer} ${evt.detail.remoteAddr}`)
  })

  const get = async () => {
    for (let delay = 5000; ; delay = Math.min(delay * 2, 120_000)) {
      try {
        return await obtain({ libp2p, issuer, store, cryptos, log })
      } catch (err) {
        log(`obtaining certificate failed, retrying in ${delay}ms: ${err.message}`)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
  }
  let cert = await get()
  tls.provision({ key: cert.key, cert: cert.chain })
  const announce = () => discovery.announce(externalAddrs(cert.altnames, wsPorts(libp2p)))
  announce()

  let renewing = false
  const timer = setInterval(() => {
    // stay connected to the issuer: it relays discovery messages
    libp2p.dial(multiaddr(issuer)).catch(err => log(`issuer unreachable: ${err.message}`))
    if (renewing || !renewDue(cert.not_before_ms, cert.not_after_ms)) return
    renewing = true
    log(`renewing certificate not_after_ms=${cert.not_after_ms}`)
    obtain({ libp2p, issuer, store, cryptos, log })
      .then(c => {
        cert = c
        tls.renew({ key: cert.key, cert: cert.chain })
        announce()
      })
      .catch(err => log(`renewal failed, keeping old certificate: ${err.message}`))
      .finally(() => { renewing = false })
  }, 10_000)

  return {
    get cert () { return cert },
    stop () {
      clearInterval(timer)
      discovery.stop()
    }
  }
}
