// DNS label <-> IP / peer id mapping; must match crates/nodetrust/src/names.rs.
import { base36 } from 'multiformats/bases/base36'

export const MAX_LABEL = 63

/** Expand an IPv6 address to its 8 hextets (no embedded IPv4 support). */
export function ipv6Segments (ip) {
  const [head, tail] = ip.includes('::') ? ip.split('::') : [ip, null]
  const h = head === '' ? [] : head.split(':')
  const t = tail == null || tail === '' ? [] : tail.split(':')
  const fill = tail == null ? [] : Array(8 - h.length - t.length).fill('0')
  const segs = [...h, ...fill, ...t]
  if (segs.length !== 8 || !segs.every(s => /^[0-9a-f]{1,4}$/i.test(s))) return null
  return segs.map(s => parseInt(s, 16).toString(16))
}

const isIpv4 = ip => /^(\d{1,3})(\.\d{1,3}){3}$/.test(ip) && ip.split('.').every(o => Number(o) <= 255 && String(Number(o)) === o)

export function ipLabel (ip) {
  if (isIpv4(ip)) return 'ip4-' + ip.replaceAll('.', '-')
  const segs = ipv6Segments(ip)
  if (segs == null) throw new Error(`not an IP address: ${ip}`)
  return 'ip6-' + segs.join('-')
}

export function parseIpLabel (label) {
  label = label.toLowerCase()
  if (label.startsWith('ip4')) {
    let rest = label.slice(3)
    if (rest.startsWith('-')) rest = rest.slice(1)
    const ip = rest.replaceAll('-', '.')
    return isIpv4(ip) ? ip : null
  }
  if (!label.startsWith('ip6')) return null
  const rest = label.slice(3)
  for (const r of [rest.startsWith('-') ? rest.slice(1) : null, rest]) {
    if (r == null) continue
    const segs = ipv6Segments(r.replaceAll('-', ':'))
    if (segs != null) return segs.join(':')
  }
  return null
}

/** @param {import('@libp2p/interface').PeerId} peerId */
export function idLabel (peerId) {
  const label = 'p' + base36.baseEncode(peerId.toMultihash().bytes)
  if (label.length > MAX_LABEL) throw new Error(`peer id label is ${label.length} chars, DNS allows ${MAX_LABEL}`)
  return label
}

export const fqdn = (label, zone) => `${label}.${zone.replace(/\.$/, '')}`.toLowerCase()

/** `[id0, ipN...]`, deduplicated, CN first */
export function certNames (peerId, ips, zone) {
  const names = [fqdn(idLabel(peerId), zone)]
  for (const ip of ips) {
    const n = fqdn(ipLabel(ip), zone)
    if (!names.includes(n)) names.push(n)
  }
  return names
}
