{
  description = "libp2p-nodetrust: DNS names and ACME certificates for libp2p nodes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      }));

      perSystem = pkgs:
        let
          lib = pkgs.lib;
          toolchain = pkgs.rust-bin.stable.latest.default.override {
            targets = [ "wasm32-unknown-unknown" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);
          src = lib.cleanSourceWith {
            src = ./.;
            filter = path: type: craneLib.filterCargoSources path type || lib.hasInfix "/examples/" path;
          };
          common = {
            inherit src;
            strictDeps = true;
            pname = "nodetrust";
            version = "0.2.0";
          };

          native = common // { cargoExtraArgs = "-p nodetrust --features sentry"; };
          nativeArtifacts = craneLib.buildDepsOnly native;

          wasm = common // {
            pname = "nodetrust-web";
            cargoExtraArgs = "-p nodetrust-web";
            CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
            doCheck = false;
          };
          wasmArtifacts = craneLib.buildDepsOnly wasm;

          nodetrust = craneLib.buildPackage (native // {
            cargoArtifacts = nativeArtifacts;
            meta = {
              mainProgram = "nodetrust";
              description = "nodetrust DNS, proof, issue servers and client";
              license = lib.licenses.mit;
            };
          });

          # wasm-bindgen-cli must match the wasm-bindgen crate version in Cargo.lock
          wasmBindgenVersion = (lib.findFirst (p: p.name == "wasm-bindgen") null
            (builtins.fromTOML (builtins.readFile ./Cargo.lock)).package).version;
          wasm-bindgen-cli = pkgs.buildWasmBindgenCli rec {
            src = pkgs.fetchCrate {
              pname = "wasm-bindgen-cli";
              version = wasmBindgenVersion;
              hash = "sha256-UsuxILm1G6PkmVw0I/JF12CRltAfCJQFOaT4hFwvR8E=";
            };
            cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
              inherit src;
              inherit (src) pname version;
              hash = "sha256-Ul52bNrGSF6BE4GBdOJoTn0cRcY+FLsCMmyHpBO1wj4=";
            };
          };

          web = craneLib.mkCargoDerivation (wasm // {
            cargoArtifacts = wasmArtifacts;
            nativeBuildInputs = [ wasm-bindgen-cli ];
            buildPhaseCargoCommand = ''
              cargo build --release -p nodetrust-web --target wasm32-unknown-unknown
            '';
            installPhaseCommand = ''
              wasm-bindgen --target web --out-dir $out \
                target/wasm32-unknown-unknown/release/nodetrust_web.wasm
            '';
          });

          js = pkgs.buildNpmPackage {
            pname = "libp2p-nodetrust-js";
            version = "0.2.0";
            src = lib.cleanSourceWith {
              src = ./js;
              filter = path: _: !(lib.hasInfix "node_modules" path);
            };
            npmDeps = pkgs.importNpmLock { npmRoot = ./js; };
            npmConfigHook = pkgs.importNpmLock.npmConfigHook;
            dontNpmBuild = true;
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              npm test
              runHook postCheck
            '';
            meta.mainProgram = "nodetrust-js";
          };

          demo = pkgs.runCommand "nodetrust-demo" { nativeBuildInputs = [ pkgs.esbuild ]; } ''
            mkdir -p $out/wasm
            cp ${./js/demo}/index.html ${./js/demo}/page.css $out/
            esbuild ${js}/lib/node_modules/libp2p-nodetrust/demo/main.js \
              --bundle --format=esm --platform=browser --outfile=$out/main.js
            cp ${web}/* $out/wasm/
          '';
        in
        {
          packages = {
            inherit nodetrust web js demo;
            default = nodetrust;
          };

          checks = {
            inherit nodetrust js;
            clippy = craneLib.cargoClippy (native // {
              cargoArtifacts = nativeArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            });
            clippy-wasm = craneLib.cargoClippy (wasm // {
              cargoArtifacts = wasmArtifacts;
              cargoClippyExtraArgs = "-- -D warnings";
            });
            fmt = craneLib.cargoFmt { inherit src; };
          } // lib.optionalAttrs pkgs.stdenv.isLinux {
            vm-test = pkgs.testers.runNixOSTest (import ./nix/test.nix {
              inherit (self.nixosModules) default;
              nodetrust = nodetrust;
              nodetrust-js = js;
            });
          };

          devShells.default = craneLib.devShell {
            packages = [ pkgs.nodejs pkgs.pebble pkgs.dig wasm-bindgen-cli pkgs.esbuild ];
          };
        };

      all = forAll perSystem;
    in
    {
      packages = nixpkgs.lib.mapAttrs (_: s: s.packages) all;
      checks = nixpkgs.lib.mapAttrs (_: s: s.checks) all;
      devShells = nixpkgs.lib.mapAttrs (_: s: s.devShells) all;

      nixosModules.default = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.nodetrust.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.nodetrust;
      };
    };
}
