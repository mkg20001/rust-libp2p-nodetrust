// One request/response exchange on a fresh stream (varint length-prefixed protobuf).
import { lpStream } from '@libp2p/utils'
import { encode, decode } from './proto.js'

export const REQUEST_TIMEOUT = 30_000

/**
 * @param {import('@libp2p/interface').Libp2p} libp2p
 * @param {import('@multiformats/multiaddr').Multiaddr} addr  must end in /p2p/<id>
 */
export async function request (libp2p, addr, protocol, reqType, req, respType) {
  const signal = AbortSignal.timeout(REQUEST_TIMEOUT)
  const stream = await libp2p.dialProtocol(addr, protocol, { signal })
  try {
    const lp = lpStream(stream)
    await lp.write(encode(reqType, req), { signal })
    const resp = await lp.read({ signal })
    return decode(respType, resp.subarray())
  } finally {
    await stream.close().catch(() => stream.abort(new globalThis.Error('close failed')))
  }
}
