#!/usr/bin/env node
// nodetrust-js client --issuer <ma> --state-dir <dir> [--listen <ma>]... [--crypto ecdsa-p256] [--no-nat]
// nodetrust-js ping <ma> [--timeout 30]
import { parseArgs } from 'node:util'
import path from 'node:path'
import fs from 'node:fs/promises'
import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { webSockets } from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { gossipsub } from '@libp2p/gossipsub'
import { uPnPNAT } from '@libp2p/upnp-nat'
import { generateKeyPair, privateKeyFromProtobuf, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import { multiaddr } from '@multiformats/multiaddr'
import { startClient, nodetrustTls, CRYPTO_NAMES } from '../src/index.js'

const log = (msg) => console.log(`${new Date().toISOString()} ${msg}`)

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    issuer: { type: 'string' },
    'state-dir': { type: 'string' },
    listen: { type: 'string', multiple: true },
    crypto: { type: 'string', multiple: true },
    'no-nat': { type: 'boolean', default: false },
    'no-dial': { type: 'boolean', default: false },
    timeout: { type: 'string', default: '30' }
  }
})

async function loadKey (stateDir) {
  const file = path.join(stateDir, 'identity.key')
  try {
    return privateKeyFromProtobuf(await fs.readFile(file))
  } catch (err) {
    if (err.code !== 'ENOENT') throw err
    const key = await generateKeyPair('Ed25519')
    await fs.mkdir(stateDir, { recursive: true })
    await fs.writeFile(file, privateKeyToProtobuf(key), { mode: 0o600 })
    return key
  }
}

const base = {
  transports: [webSockets(), tcp()],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()]
}

const [cmd, arg] = positionals
if (cmd === 'client') {
  if (values.issuer == null || values['state-dir'] == null) throw new Error('--issuer and --state-dir are required')
  const cryptos = (values.crypto ?? ['ecdsa-p256', 'rsa']).map(c => {
    if (CRYPTO_NAMES[c] == null) throw new Error(`unknown crypto ${c}`)
    return CRYPTO_NAMES[c]
  })
  const libp2p = await createLibp2p({
    ...base,
    privateKey: await loadKey(values['state-dir']),
    addresses: { listen: values.listen ?? ['/ip4/0.0.0.0/tcp/0/ws'] },
    services: {
      identify: identify(),
      ping: ping(),
      pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }),
      nodetrustTls: nodetrustTls(),
      ...(values['no-nat'] ? {} : { nat: uPnPNAT() })
    }
  })
  log(`starting peer=${libp2p.peerId}`)
  for (const ma of libp2p.getMultiaddrs()) log(`listening ${ma}`)
  await startClient(libp2p, { issuer: values.issuer, stateDir: values['state-dir'], cryptos, dial: !values['no-dial'], log })
} else if (cmd === 'ping') {
  const target = multiaddr(arg)
  const libp2p = await createLibp2p({ ...base, services: { identify: identify(), ping: ping() } })
  const rtt = await libp2p.services.ping.ping(target, { signal: AbortSignal.timeout(Number(values.timeout) * 1000) })
  console.log(`pong from ${target.getComponents().at(-1)?.value} in ${rtt}ms`)
  await libp2p.stop()
} else {
  console.error('usage: nodetrust-js client --issuer <ma> --state-dir <dir> [--listen <ma>] | ping <ma>')
  process.exit(2)
}
