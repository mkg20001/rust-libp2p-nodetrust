// Certificate keys and CSRs via WebCrypto + @peculiar/x509 (works in Node >= 20 and browsers).
import 'reflect-metadata' // required by @peculiar/x509
import * as x509 from '@peculiar/x509'
import { Crypto } from './proto.js'

x509.cryptoProvider.set(globalThis.crypto)
const subtle = globalThis.crypto.subtle

const ALGS = {
  [Crypto.ECDSA_P256]: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
  [Crypto.RSA]: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
}

export const CRYPTO_NAMES = { 'ecdsa-p256': Crypto.ECDSA_P256, rsa: Crypto.RSA }

export async function generateKey (crypto) {
  const keys = await subtle.generateKey(ALGS[crypto], true, ['sign', 'verify'])
  return x509.PemConverter.encode(await subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY')
}

/** Imports a PKCS#8 PEM key of type `crypto`, plus its public half. Throws if the type differs. */
async function importKey (pem, crypto) {
  const alg = ALGS[crypto]
  const privateKey = await subtle.importKey('pkcs8', x509.PemConverter.decodeFirst(pem), alg, true, ['sign'])
  const jwk = await subtle.exportKey('jwk', privateKey)
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi']) delete jwk[k]
  jwk.key_ops = ['verify']
  const publicKey = await subtle.importKey('jwk', jwk, alg, true, ['verify'])
  return { privateKey, publicKey }
}

export async function keyMatches (pem, crypto) {
  try {
    await importKey(pem, crypto)
    return true
  } catch {
    return false
  }
}

/** DER PKCS#10 request for `names` (first is the CN). */
export async function csr (pem, crypto, names) {
  const keys = await importKey(pem, crypto)
  const req = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${names[0]}`,
    keys,
    signingAlgorithm: ALGS[crypto],
    extensions: [new x509.SubjectAlternativeNameExtension(names.map(value => ({ type: 'dns', value })))]
  })
  return new Uint8Array(req.rawData)
}

/** Inspect the first certificate of a PEM chain. */
export function parseChain (chain) {
  const first = chain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)
  if (first == null) throw new Error('no certificate in chain')
  const cert = new x509.X509Certificate(first[0])
  return { notBefore: cert.notBefore.getTime(), notAfter: cert.notAfter.getTime(), issuer: cert.issuer }
}

/** Renew once less than a third of the lifetime is left. */
export const renewDue = (notBefore, notAfter, now = Date.now()) => now >= notAfter - (notAfter - notBefore) / 3
