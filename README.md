# libp2p-nodetrust (Rust)

> Why not give every libp2p node an `ip4-1-2-3-4.<zone>` address and a certificate?

Browsers can only open secure websockets to other nodes, so they all crowd onto a few
bootstrap and relay nodes. nodetrust gives every reachable libp2p node:

* a DNS name derived from its IP,
* a CA-signed certificate for that name (via ACME DNS-01),
* a WSS listener, announced over pubsub so browsers and other nodes can dial it directly.

This is a Rust rebuild of [mkg20001/libp2p-nodetrust](https://github.com/mkg20001/libp2p-nodetrust).
It includes the servers, a native client, a wasm browser client and a js-libp2p client. The
wire format is described in [PROTOCOL.md](PROTOCOL.md).

## Components

| Path | What |
|---|---|
| `crates/nodetrust` | library + `nodetrust` binary: `dns`, `proof`, `issue`, `client`, `keygen`, `pubkey`, `ping`, `debug …` |
| `crates/nodetrust-web` | wasm32 browser client (`start(issuer, onPeer, onConnect)`) |
| `js/` | `libp2p-nodetrust` npm package: Node client (issuance, WSS, renewal), browser discovery, `nodetrust-js` CLI |
| `js/demo/` | demo page that switches between the JS and wasm clients (`?impl=js\|wasm&issuer=…`) |
| `nix/module.nix` | NixOS module `services.nodetrust.{dns,proof,issue,client}` |
| `nix/test.nix` | NixOS VM test: Pebble CA, 3 servers, 2 Rust clients and 1 JS client |

## Running

```sh
nix build .#nodetrust                  # or: cargo build --release -p nodetrust
nodetrust keygen --out proof.key       # proof signing key; its public_key goes into issue.toml
nodetrust dns   --config examples/dns.toml
nodetrust proof --config examples/proof.toml
nodetrust issue --config examples/issue.toml
nodetrust client --config examples/client.toml
```

On NixOS:

```nix
{
  inputs.nodetrust.url = "github:mkg20001/rust-libp2p-nodetrust";
  # …
  imports = [ inputs.nodetrust.nixosModules.default ];
  services.nodetrust.client = {
    enable = true;
    openFirewall = true;
    settings = {
      issuer = "/dns4/issue.nt.example.org/tcp/25893/p2p/12D3KooW…";
      wss_listen = "/ip4/0.0.0.0/tcp/4443/tls/ws";
    };
  };
}
```

See `examples/*.toml` for every option. Set `RUST_LOG` to change the log level. Builds with the
`sentry` feature (the flake's default) report to `SENTRY_DSN` when it is set.

JS client:

```sh
nix build .#js
nodetrust-js client --issuer /ip4/…/tcp/25893/p2p/… --state-dir ./state --listen /ip4/0.0.0.0/tcp/4445/ws
```

Demo: `nix build .#demo`, serve `result/` over HTTP and open
`index.html?issuer=/ip4/<issuer>/tcp/25894/ws/p2p/<id>`.

## Development

```sh
nix develop
cargo test
(cd js && npm install && npm test)
nix flake check                      # clippy (native + wasm), fmt, unit tests, JS tests, demo e2e, VM test
nix build .#checks.x86_64-linux.vm-test -L
nix build .#checks.x86_64-linux.demo-e2e -L   # Playwright: demo page with both implementations
(cd js && DEMO_DIR=$(nix build --print-out-paths ..#demo) npm run test:demo)
```

## Changes from v1

* Clients send a CSR; the private key never leaves the node.
* Proofs are bound to the requesting peer.
* DNS-01 requests outside the zone or from non-admins are rejected with an error reply.
* IPv6 names are fully expanded.
* The DNS server now behaves like a real authority (SOA, NXDOMAIN/NODATA, RFC 8482).
* Certificates are swapped without restarting the WSS listener.
* Key types: ECDSA P-256 and RSA.

## License

MIT
