// Wire messages, parsed at runtime from the shared schema (proto/nodetrust.proto).
import protobuf from 'protobufjs'
import schema from './schema.js'

const root = protobuf.parse(schema).root

export const PROOF_PROTOCOL = '/nodetrust/proof/2.0.0'
export const INFO_PROTOCOL = '/nodetrust/issue/info/2.0.0'
export const ISSUE_PROTOCOL = '/nodetrust/issue/2.0.0'
export const DNS01_PROTOCOL = '/nodetrust/dns-01/2.0.0'
export const DISCOVERY_TOPIC = '_nodetrust_discovery_v2'

export const Error = root.lookupEnum('Error').values
export const Crypto = root.lookupEnum('Crypto').values
export const AddressType = root.lookupEnum('AddressType').values

/** @param {string} type @param {object} obj @returns {Uint8Array} */
export function encode (type, obj) {
  const T = root.lookupType(type)
  const err = T.verify(obj)
  if (err != null) throw new TypeError(`${type}: ${err}`)
  return T.encode(T.fromObject(obj)).finish()
}

/** @param {string} type @param {Uint8Array} bytes */
export function decode (type, bytes) {
  const T = root.lookupType(type)
  return T.toObject(T.decode(bytes), { defaults: true, enums: Number, longs: Number, arrays: true })
}

/** name of an Error value, for messages */
export function errorName (code) {
  return Object.keys(Error).find(k => Error[k] === code) ?? `E_${code}`
}
