# Agent notes

* Rust workspace (`crates/`), js-libp2p package (`js/`), Nix (`flake.nix`, `nix/`).
* Wire format: `proto/nodetrust.proto` is the source of truth. The Rust structs in
  `crates/nodetrust/src/proto.rs` are hand-derived, and `js/src/schema.js` is a verbatim copy
  (checked by `js/test/test.js`). Change all three together.
* The DNS label encoding lives in `crates/nodetrust/src/names.rs` and `js/src/names.js`. Both
  test the same vector; keep them in sync.
* Tests: `cargo test`, `npm test` (in `js/`), and the end-to-end check
  `nix build .#checks.x86_64-linux.vm-test -L`.
* `nix/test-keys/` holds throwaway keys for the VM test only.
