// Obtain a certificate from an issue server (Node: needs TCP to reach the proof servers).
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromMultihash } from '@libp2p/peer-id'
import * as Digest from 'multiformats/hashes/digest'
import { INFO_PROTOCOL, ISSUE_PROTOCOL, PROOF_PROTOCOL, Error, decode, errorName } from './proto.js'
import { request } from './rpc.js'
import { certNames } from './names.js'
import { generateKey, keyMatches, csr, parseChain } from './tlskey.js'

/**
 * @param {object} opts
 * @param {import('@libp2p/interface').Libp2p} opts.libp2p
 * @param {string} opts.issuer issue server multiaddr (…/p2p/<id>)
 * @param {ReturnType<import('./store.js').createStore>} opts.store
 * @param {number[]} opts.cryptos Crypto values in order of preference
 * @returns {Promise<{cn, altnames, not_before_ms, not_after_ms, from_cache, issuer, chain, key}>}
 */
export async function obtain ({ libp2p, issuer, store, cryptos, log = () => {} }) {
  const issuerAddr = multiaddr(issuer)
  const info = await request(libp2p, issuerAddr, INFO_PROTOCOL, 'IssueInfoRequest', {}, 'IssueInfo')
  log(`issuer info domain=${info.domain} proof_servers=${info.proofs.length}`)
  const crypto = cryptos.find(c => info.supportedCryptos.includes(c))
  if (crypto == null) throw new globalThis.Error('issuer supports none of our key types')

  const results = await Promise.allSettled(info.proofs.map(async server => {
    const peer = peerIdFromMultihash(Digest.decode(server.id))
    let last = new globalThis.Error('no addresses')
    for (const raw of server.addrs) {
      let addr = multiaddr(raw)
      if (addr.getComponents().at(-1)?.name !== 'p2p') addr = addr.encapsulate(`/p2p/${peer}`)
      try {
        const r = await request(libp2p, addr, PROOF_PROTOCOL, 'ProofRequest', {}, 'ProofResponse')
        if (r.error === Error.OK && r.proof != null) return r.proof
        last = new globalThis.Error(`proof error ${errorName(r.error)}`)
      } catch (err) {
        last = err
      }
    }
    throw last
  }))
  const proofs = []
  results.forEach((r, i) => {
    const display = info.proofs[i].display
    if (r.status === 'fulfilled') {
      log(`acquired proof server=${display}`)
      proofs.push(r.value)
    } else {
      log(`failed to get proof server=${display}: ${r.reason?.message}`)
    }
  })
  if (proofs.length === 0) throw new globalThis.Error('could not acquire a single proof')

  const ips = proofs.flatMap(p => decode('Proof', p.proof).addrs.map(a => a.address))
  const names = certNames(libp2p.peerId, ips, info.domain)

  let key = await store.read('tls.key')
  if (key == null || !(await keyMatches(key, crypto))) {
    key = await generateKey(crypto)
    await store.write('tls.key', key, { secret: true })
  }
  const resp = await request(libp2p, issuerAddr, ISSUE_PROTOCOL, 'IssueRequest',
    { proofs, supportedCryptos: [crypto], csr: await csr(key, crypto, names) }, 'IssueResponse')
  if (resp.error !== Error.OK) throw new globalThis.Error(`issue error ${errorName(resp.error)}: ${resp.message}`)

  const chain = new TextDecoder().decode(resp.chain)
  const parsed = parseChain(chain)
  const state = {
    cn: resp.cn,
    altnames: resp.altnames,
    not_before_ms: parsed.notBefore,
    not_after_ms: parsed.notAfter,
    from_cache: resp.fromCache,
    issuer: parsed.issuer,
    chain
  }
  await store.write('cert.json', JSON.stringify(state, null, 2))
  log(`certificate obtained cn=${state.cn} altnames=${state.altnames.join(',')} not_after_ms=${state.not_after_ms}`)
  return { ...state, key }
}
