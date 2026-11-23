import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { gossipsub } from '@libp2p/gossipsub'
import { peerIdFromString } from '@libp2p/peer-id'
import schema from '../src/schema.js'
import {
  ipLabel, parseIpLabel, idLabel, certNames, encode, decode, Crypto, Error,
  encodeAnnounce, decodeAnnounce, startDiscovery, externalAddrs, renewDue
} from '../src/index.js'
import { generateKey, csr, keyMatches } from '../src/tlskey.js'

// shared vector with crates/nodetrust/src/names.rs
const PEER = '12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA'
const PEER_LABEL = 'p0cllw0agyvgb9nhnvt2elffail9ggdvagkdsouqdvb4krqmudjzhcdes8b'

test('schema copy matches proto/nodetrust.proto', () => {
  const url = new URL('../../proto/nodetrust.proto', import.meta.url)
  if (!fs.existsSync(url)) return // packaged without the repo
  assert.equal(schema, fs.readFileSync(url, 'utf8'))
})

test('names', () => {
  for (const ip of ['127.0.0.1', '8.8.8.8', '::1', '2001:db8::', 'fe80::1:2']) {
    const label = ipLabel(ip)
    assert.ok(!label.endsWith('-') && label.length <= 63, label)
    assert.equal(parseIpLabel(label), ip.includes(':') ? label.slice(4).replaceAll('-', ':') : ip)
  }
  assert.equal(ipLabel('::1'), 'ip6-0-0-0-0-0-0-0-1')
  assert.equal(parseIpLabel('ip4127-0-0-1'), '127.0.0.1')
  assert.equal(parseIpLabel('ip6--1'), '0:0:0:0:0:0:0:1')
  assert.equal(parseIpLabel('ip4-1-2-3-999'), null)
  assert.equal(idLabel(peerIdFromString(PEER)), PEER_LABEL)
  assert.deepEqual(certNames(peerIdFromString(PEER), ['1.2.3.4', '1.2.3.4'], 'NT.test.'),
    [`${PEER_LABEL}.nt.test`, 'ip4-1-2-3-4.nt.test'])
  assert.deepEqual(externalAddrs(['ip4-1-2-3-4.nt.test', 'ip6-0-0-0-0-0-0-0-1.nt.test'], { v4: 4443 }),
    ['/dns4/ip4-1-2-3-4.nt.test/tcp/4443/tls/ws'])
  assert.ok(!renewDue(0, 300, 199) && renewDue(0, 300, 200))
})

test('proto roundtrip', () => {
  const req = { proofs: [{ proof: new Uint8Array([1]), signature: new Uint8Array([2]) }], supportedCryptos: [Crypto.ECDSA_P256], csr: new Uint8Array([3]) }
  const out = decode('IssueRequest', encode('IssueRequest', req))
  assert.deepEqual(out.supportedCryptos, [Crypto.ECDSA_P256])
  assert.deepEqual([...out.proofs[0].signature], [2])
  assert.equal(decode('IssueResponse', encode('IssueResponse', { error: Error.E_INVALID_PROOF })).error, Error.E_INVALID_PROOF)
  const a = '/dns4/ip4-1-2-3-4.nt.test/tcp/4443/tls/ws'
  assert.deepEqual(decodeAnnounce(encodeAnnounce([a, `${a}/p2p/${PEER}`])), [a, a])
})

test('csr', async () => {
  for (const c of [Crypto.ECDSA_P256, Crypto.RSA]) {
    const key = await generateKey(c)
    assert.ok(await keyMatches(key, c))
    const der = await csr(key, c, ['a.nt.test', 'b.nt.test'])
    assert.equal(der[0], 0x30)
  }
})

test('discovery between two nodes', async () => {
  const mk = () => createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: { identify: identify(), pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }) }
  })
  const [a, b] = await Promise.all([mk(), mk()])
  let db
  const seen = new Promise(resolve => { db = startDiscovery(b, { dial: false, onPeer: (peer, addrs) => resolve({ peer, addrs }) }) })
  const da = startDiscovery(a, { dial: false })
  await a.dial(b.getMultiaddrs()[0])
  const addr = '/dns4/ip4-1-2-3-4.nt.test/tcp/4443/tls/ws'
  const timer = setInterval(() => da.announce([addr]), 500)
  const got = await seen
  clearInterval(timer)
  assert.equal(got.peer, a.peerId.toString())
  assert.deepEqual(got.addrs, [addr])
  da.stop()
  db.stop()
  await Promise.all([a.stop(), b.stop()])
})
