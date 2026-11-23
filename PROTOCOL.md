# libp2p-nodetrust protocol, version 2

Messages are defined in [`proto/nodetrust.proto`](proto/nodetrust.proto). Each protocol is one
request and one response on a fresh libp2p stream (noise + yamux). Each message is prefixed
with its length as an unsigned varint.

Version 2 is not wire compatible with v1 (js-libp2p 0.23: secio, spdy/mplex, floodsub).

## Roles

| Role | Protocols served | Notes |
|---|---|---|
| Client | – | wants a certificate |
| Proof server | `/nodetrust/proof/2.0.0` | signs the IPs a peer is connected from |
| Issue server | `/nodetrust/issue/info/2.0.0`, `/nodetrust/issue/2.0.0` | gets ACME certificates |
| DNS server | DNS (UDP+TCP), `/nodetrust/dns-01/2.0.0` | authoritative for the zone |

DNS and issue servers subscribe to the discovery topic and relay it. They can also act as
circuit relays.

## DNS names

| Name | Record |
|---|---|
| `ip4-1-2-3-4.<zone>` | `A 1.2.3.4` |
| `ip6-2001-db8-0-0-0-0-0-1.<zone>` | `AAAA 2001:db8::1` (always issued fully expanded) |
| `p<base36 lower(peer id bytes)>.<zone>` | `TXT "id=<peer id>"`; this name is the certificate CN |
| `_acme-challenge.<name>.<zone>` | `TXT` DNS-01 values pushed by issue servers |
| `<zone>` | `SOA`, `NS` |

* Lookups are case-insensitive. ANY queries get `HINFO "RFC8482" ""`. Names outside the zone
  get `REFUSED`, unknown names `NXDOMAIN`, and existing names of another type NODATA + SOA.
* IPv6 names are fully expanded because a compressed address can start or end with `-`, which
  is not a valid hostname label.
* The decoder also accepts the v1 forms `ip41-2-3-4` and `ip6--1`.

## Proofs

A proof server reads the remote address of every open plain TCP connection from the
requesting peer and signs:

```
Proof { id = requesting peer id, timestamp = ms since epoch, addrs = [Address] }
ProofWrapper { proof = encoded Proof, signature = sign(proof key, proof) }
```

The signature covers the encoded bytes as sent, so the proof is never re-encoded. Every proof
server shares one proof key. An issue server accepts a proof if:

* the signature is from a trusted proof key,
* `|timestamp - now| <= 5 min`,
* `id` is the peer that sent the issue request. (v1 didn't check this, so anyone could replay
  a proof they had captured.)

## Issuing

1. The client sends `IssueInfoRequest` to `/nodetrust/issue/info/2.0.0`. The response
   `IssueInfo` lists the domain, the proof servers and the key types the server supports.
2. The client requests a proof from every proof server in parallel over TCP. Failures are
   skipped; zero proofs is an error.
3. The client computes its names: `[id name] + ip names`, in proof order, deduplicated.
4. The client generates a key (`ECDSA_P256` or `RSA`; the client keeps it) and builds a CSR for
   exactly those names.
5. The client sends `IssueRequest { proofs, supported_cryptos, csr }` to
   `/nodetrust/issue/2.0.0`. The server:
   * verifies every proof (`E_INVALID_PROOF`),
   * checks that the CSR key type is supported by both sides (`E_NO_MATCHING_CRYPTO`),
   * checks the CSR's self-signature and that its names equal the computed names
     (`E_INVALID_REQUEST`),
   * returns a cached certificate if one exists for the same peer, names and public key with
     more than a third of its lifetime left (`from_cache = true`),
   * otherwise places an ACME order and pushes each DNS-01 value to its DNS servers over
     `/nodetrust/dns-01/2.0.0`. A DNS server accepts only allowlisted admin peers
     (`E_NOT_AUTHORIZED`) and only names inside its zone. It then finalizes the order with the
     client's CSR. A rate-limit error from the CA maps to `E_RATE_LIMIT`.
6. `IssueResponse` carries the PEM `cert`, `chain` and `ca`, plus `cn`, `altnames`,
   `validity` (notAfter in ms) and `crypto_type`. On failure it carries `message`.

## Serving and discovery

* The client serves WSS with the certificate and maps the port with UPnP where it can.
* Every 10 s it publishes `Announce { addr = [/dns4|dns6/<ip name>/tcp/<port>/tls/ws] }` on
  gossipsub topic `_nodetrust_discovery_v2`, with signed messages. The message source is the
  announcing peer.
* Peers receiving an announcement add the addresses and may dial them. Browsers can only dial
  `/tls/ws`.
* Clients renew once less than a third of the certificate lifetime is left, and swap the
  served certificate without restarting the listener.
