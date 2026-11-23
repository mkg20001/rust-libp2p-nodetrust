// Demo: run the browser client in either implementation behind one interface:
//   start(issuer, { onPeer(peer, addrs), onConnect(peer, addr), log(msg) }) -> { peerId, stop() }
import { createLibp2p } from 'libp2p'
import { webSockets } from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { gossipsub } from '@chainsafe/libp2p-gossipsub'
import { multiaddr } from '@multiformats/multiaddr'
import { startDiscovery } from '../src/index.js'

const impls = {
  async js (issuer, { onPeer, onConnect, log }) {
    const libp2p = await createLibp2p({
      transports: [webSockets()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      connectionGater: { denyDialMultiaddr: () => false },
      services: { identify: identify(), ping: ping(), pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }) }
    })
    libp2p.addEventListener('connection:open', e => onConnect(e.detail.remotePeer.toString(), e.detail.remoteAddr.toString()))
    const discovery = startDiscovery(libp2p, { onPeer, secureOnly: true, log })
    await libp2p.dial(multiaddr(issuer))
    return {
      peerId: libp2p.peerId.toString(),
      async stop () {
        discovery.stop()
        await libp2p.stop()
      }
    }
  },
  async wasm (issuer, { onPeer, onConnect }) {
    // built by `nix build .#web`, copied to ./wasm by `nix build .#demo`
    const mod = await import(/* webpackIgnore: true */ new URL('./wasm/nodetrust_web.js', import.meta.url).href)
    await mod.default()
    const node = mod.start(issuer, onPeer, onConnect)
    return { peerId: node.peerId, async stop () { node.stop() } }
  }
}

const $ = id => document.getElementById(id)
const params = new URLSearchParams(location.search)
if (params.has('issuer')) $('issuer').value = params.get('issuer')
const implParam = params.get('impl')
if (implParam in impls) document.querySelector(`input[name=impl][value=${implParam}]`).checked = true

const log = msg => {
  const line = `${new Date().toLocaleTimeString()} ${msg}\n`
  $('log').textContent = (line + $('log').textContent).slice(0, 50_000)
}
const upsert = (list, key, text) => {
  let li = list.querySelector(`[data-key="${CSS.escape(key)}"]`)
  if (li == null) {
    li = document.createElement('li')
    li.dataset.key = key
    list.append(li)
  }
  li.textContent = text
}

let running = null

async function stop () {
  await running.stop()
  running = null
  $('state').value = 'stopped'
  $('toggle').textContent = 'Start'
  log('stopped')
}

async function start () {
  const impl = document.querySelector('input[name=impl]:checked').value
  $('peers').replaceChildren()
  $('conns').replaceChildren()
  try {
    running = await impls[impl]($('issuer').value.trim(), {
      log,
      onPeer: (peer, addrs) => { upsert($('peers'), peer, `${peer} ${[...addrs].join(' ')}`); log(`discovered ${peer}`) },
      onConnect: (peer, addr) => { upsert($('conns'), peer, `${peer} via ${addr}`); log(`connected ${peer}`) }
    })
  } catch (err) {
    log(`error: ${err.message ?? err}`)
    return
  }
  $('state').value = `running (${impl}) as ${running.peerId}`
  $('toggle').textContent = 'Stop'
  log(`started ${impl} node ${running.peerId}`)
}

const busy = async fn => {
  $('toggle').disabled = true
  try { await fn() } finally { $('toggle').disabled = false }
}

$('controls').addEventListener('submit', e => {
  e.preventDefault()
  busy(running == null ? start : stop)
})
// switching implementation restarts the node with the other one
document.querySelectorAll('input[name=impl]').forEach(r => r.addEventListener('change', () => {
  if (running != null) busy(async () => { await stop(); await start() })
}))
