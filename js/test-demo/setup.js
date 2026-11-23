// Fixture for the demo tests: serves the built demo (DEMO_DIR) and runs two libp2p nodes:
// a hub on /ws standing in for the issue server (pubsub relay), and a peer with a /tls/ws
// listener (self-signed) that announces itself via discovery, like a nodetrust client.
import 'reflect-metadata'
import http from 'node:http'
import fs from 'node:fs/promises'
import path from 'node:path'
import * as x509 from '@peculiar/x509'
import { createLibp2p } from 'libp2p'
import { webSockets } from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { gossipsub } from '@libp2p/gossipsub'
import { startDiscovery } from '../src/index.js'

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm' }

function serve (root) {
  const server = http.createServer(async (req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname)
    const file = path.resolve(root, `.${rel.endsWith('/') ? `${rel}index.html` : rel}`)
    if (!file.startsWith(path.resolve(root) + path.sep)) return res.writeHead(403).end()
    try {
      const body = await fs.readFile(file)
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] ?? 'application/octet-stream' }).end(body)
    } catch {
      res.writeHead(404).end()
    }
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)))
}

async function selfSigned () {
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=127.0.0.1',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    keys,
    signingAlgorithm: alg,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'ip', value: '127.0.0.1' }])]
  })
  const key = x509.PemConverter.encode(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY')
  return { key, cert: cert.toString('pem') }
}

const node = (listen, ws = webSockets()) => createLibp2p({
  addresses: { listen: [listen] },
  transports: [ws],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()],
  connectionGater: { denyDialMultiaddr: () => false },
  services: { identify: identify(), pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }) }
})

export default async function setup () {
  const root = process.env.DEMO_DIR
  if (root == null) throw new Error('DEMO_DIR must point at the built demo (nix build .#demo)')
  const web = await serve(root)

  const hub = await node('/ip4/127.0.0.1/tcp/0/ws')
  const hubDiscovery = startDiscovery(hub, { dial: false })

  const peer = await node('/ip4/127.0.0.1/tcp/0/tls/ws', webSockets({ https: await selfSigned() }))
  const peerDiscovery = startDiscovery(peer, { dial: false })
  await peer.dial(hub.getMultiaddrs()[0])
  const wss = peer.getMultiaddrs()[0].toString().replace(/\/p2p\/.*$/, '')
  // announce often so a freshly started browser node hears it quickly
  const timer = setInterval(() => peerDiscovery.announce([wss]), 1000)

  process.env.DEMO_URL = `http://127.0.0.1:${web.address().port}/`
  process.env.HUB_ADDR = hub.getMultiaddrs()[0].toString()
  process.env.HUB_ID = hub.peerId.toString()
  process.env.PEER_ID = peer.peerId.toString()

  return async () => {
    clearInterval(timer)
    peerDiscovery.stop()
    hubDiscovery.stop()
    await Promise.all([peer.stop(), hub.stop()])
    web.close()
  }
}
