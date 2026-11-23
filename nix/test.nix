# End-to-end test: DNS + proof + issue servers with Pebble as ACME CA; alice and bob run the Rust
# client, carol the JS client. Checks DNS records, issuance, TLS verification, libp2p WSS
# connectivity both ways between implementations, pubsub discovery, auth failures and in-place
# renewal of short-lived (5 minute) certificates.
{ default, nodetrust, nodetrust-js }:
{ lib, pkgs, ... }:

let
  ids = {
    dns = "12D3KooWRSxcSjE7GLQ8w41wkgWJMUpzCf4c4K2EM6jxcCPXyWjb";
    proof = "12D3KooWMFNSRufbxsKDy8VsRak21Qv93DZzMLK1j2cWnt69Uhxx";
    issue = "12D3KooWDxx9CK6QJ4tVXNx8qRPJzKQDCGDYP1VDAmGE5xkdVT19";
  };
  proofPubKey = "CAESIHnnSRr0rA+NacjxVtrjU5gIK9zZVKc9n8TxUFTJYs3m";
  zone = "nt.test";
  root = "/etc/pebble-root.pem"; # written by the test script (Pebble's root is generated at start)
  minica = "${pkgs.pebble.src}/test/certs/pebble.minica.pem";

  client = { nodes, ... }: {
    imports = [ default ];
    services.nodetrust.package = nodetrust;
    networking.nameservers = [ nodes.server.networking.primaryIPAddress ];
    environment.systemPackages = [ nodetrust pkgs.dig pkgs.jq pkgs.openssl pkgs.curl ];
    services.nodetrust.client = {
      enable = true;
      openFirewall = true;
      listen = [ "/ip4/0.0.0.0/tcp/25900" ];
      settings = {
        issuer = "/ip4/${nodes.server.networking.primaryIPAddress}/tcp/25893/p2p/${ids.issue}";
        wss_listen = "/ip4/0.0.0.0/tcp/4443/tls/ws";
        nat = false;
        ca_file = root;
      };
    };
    # started by the test script once the CA root is in place
    systemd.services.nodetrust-client.wantedBy = lib.mkForce [ ];
  };
in
{
  name = "nodetrust";

  nodes = {
    server = { nodes, ... }: {
      imports = [ default ];
      services.nodetrust.package = nodetrust;
      environment.systemPackages = [ nodetrust pkgs.dig pkgs.curl ];
      networking.firewall.allowedTCPPorts = [ 15000 ];

      services.nodetrust.dns = {
        enable = true;
        openFirewall = true;
        identityFile = ./test-keys/dns.key;
        listen = [ "/ip4/0.0.0.0/tcp/25891" ];
        settings = {
          listen = [ "0.0.0.0:53" "[::]:53" ];
          inherit zone;
          ns = [ "ns1.${zone}" ];
          admins = [ ids.issue ];
          records."ns1.${zone}" = [ nodes.server.networking.primaryIPAddress ];
          txt_ttl = 600;
        };
      };

      services.nodetrust.proof = {
        enable = true;
        openFirewall = true;
        identityFile = ./test-keys/proof-id.key;
        keyFile = ./test-keys/proof.key;
        listen = [ "/ip4/0.0.0.0/tcp/25892" "/ip6/::/tcp/25892" ];
      };

      services.nodetrust.issue = {
        enable = true;
        openFirewall = true;
        identityFile = ./test-keys/issue.key;
        acmeCaFile = minica;
        listen = [ "/ip4/0.0.0.0/tcp/25893" "/ip4/0.0.0.0/tcp/25894/ws" ];
        settings = {
          inherit zone;
          directory = "https://localhost:14000/dir";
          dns = [ "/ip4/127.0.0.1/tcp/25891/p2p/${ids.dns}" ];
          proof_keys = [ proofPubKey ];
          proof_servers = [
            { display = "v4"; addrs = [ "/ip4/${nodes.server.networking.primaryIPAddress}/tcp/25892/p2p/${ids.proof}" ]; }
            { display = "v6"; addrs = [ "/ip6/${nodes.server.networking.primaryIPv6Address}/tcp/25892/p2p/${ids.proof}" ]; }
          ];
        };
      };
      systemd.services.nodetrust-issue = {
        after = [ "pebble.service" "nodetrust-dns.service" ];
        requires = [ "pebble.service" ];
      };

      systemd.services.pebble = {
        wantedBy = [ "multi-user.target" ];
        environment = {
          PEBBLE_VA_NOSLEEP = "1";
          PEBBLE_WFE_NONCEREJECT = "0";
        };
        serviceConfig = {
          ExecStart = "${pkgs.pebble}/bin/pebble -config ${pkgs.writeText "pebble.json" (builtins.toJSON {
            pebble = {
              listenAddress = "0.0.0.0:14000";
              managementListenAddress = "0.0.0.0:15000";
              certificate = "${pkgs.pebble.src}/test/certs/localhost/cert.pem";
              privateKey = "${pkgs.pebble.src}/test/certs/localhost/key.pem";
              httpPort = 5002;
              tlsPort = 5001;
              ocspResponderURL = "";
              externalAccountBindingRequired = false;
              retryAfter = { authz = 1; order = 1; };
              profiles.default = { description = "5 minute certificates"; validityPeriod = 300; };
            };
          })} -dnsserver 127.0.0.1:53";
          DynamicUser = true;
        };
      };
    };

    alice = client;
    bob = client;

    carol = { nodes, ... }: {
      networking.nameservers = [ nodes.server.networking.primaryIPAddress ];
      networking.firewall.allowedTCPPorts = [ 4445 ];
      environment.systemPackages = [ nodetrust-js pkgs.jq ];
      systemd.services.nodetrust-js = {
        environment.NODE_EXTRA_CA_CERTS = root;
        serviceConfig = {
          ExecStart = "${lib.getExe nodetrust-js} client --issuer /ip4/${nodes.server.networking.primaryIPAddress}/tcp/25893/p2p/${ids.issue} --state-dir /var/lib/nodetrust-js --listen /ip4/0.0.0.0/tcp/4445/ws --no-nat";
          StateDirectory = "nodetrust-js";
          DynamicUser = true;
        };
      };
    };
  };

  testScript = { nodes, ... }: let
    ip = n: nodes.${n}.networking.primaryIPAddress;
    ip6 = n: nodes.${n}.networking.primaryIPv6Address;
  in ''
    import json

    def label6(addr):
        import ipaddress
        return "ip6-" + "-".join(format(int(s, 16), "x") for s in ipaddress.ip_address(addr).exploded.split(":"))

    def cert(machine, path="/var/lib/nodetrust-client/cert.json"):
        return json.loads(machine.succeed(f"cat {path}"))

    start_all()
    server.wait_for_unit("pebble.service")
    for unit in ["nodetrust-dns", "nodetrust-proof", "nodetrust-issue"]:
        server.wait_for_unit(f"{unit}.service")
    server.wait_for_open_port(53)
    server.wait_for_open_port(25893)

    with subtest("dns records"):
        q = "dig +short @${ip "server"}"
        alice.succeed(f"{q} ip4-${lib.replaceStrings ["."] ["-"] (ip "alice")}.${zone} A | grep -x ${ip "alice"}")
        alice.succeed(f"{q} IP4${lib.replaceStrings ["."] ["-"] (ip "alice")}.NT.test A | grep -x ${ip "alice"}")
        alice.succeed(f"{q} {label6('${ip6 "alice"}')}.${zone} AAAA | grep -x ${ip6 "alice"}")
        alice.succeed(f"{q} ${zone} NS | grep -x ns1.${zone}.")
        alice.succeed(f"{q} ns1.${zone} A | grep -x ${ip "server"}")
        alice.succeed(f"{q} ${zone} SOA | grep ns1.${zone}.")
        alice.succeed(f"{q} anything.${zone} ANY | grep RFC8482")
        alice.succeed("dig @${ip "server"} junk.${zone} A | grep 'status: NXDOMAIN'")
        alice.succeed("dig @${ip "server"} example.org A | grep 'status: REFUSED'")

    with subtest("fetch pebble root"):
        for m in [alice, bob, carol]:
            m.succeed(
                "${pkgs.curl}/bin/curl -sf --cacert ${minica} --resolve pebble:15000:${ip "server"} "
                "https://pebble:15000/roots/0 > ${root}"
            )

    with subtest("dns-01 only from admins"):
        out = alice.fail("nodetrust debug dns01 /ip4/${ip "server"}/tcp/25891/p2p/${ids.dns} ip4-1-2-3-4.${zone} evil 2>&1")
        assert "ENotAuthorized" in out, out

    with subtest("proofs are bound to the requesting peer"):
        alice.succeed("nodetrust debug proof /ip4/${ip "server"}/tcp/25892/p2p/${ids.proof} --out /tmp/proof")
        out = alice.fail("nodetrust debug issue /ip4/${ip "server"}/tcp/25893/p2p/${ids.issue} --proof /tmp/proof 2>&1")
        assert "EInvalidProof" in out and "another peer" in out, out

    with subtest("alice obtains a certificate"):
        alice.systemctl("start nodetrust-client")
        alice.wait_until_succeeds("test -s /var/lib/nodetrust-client/cert.json", timeout=180)
        c = cert(alice)
        alice_id = alice.succeed("nodetrust pubkey --key /var/lib/nodetrust-client/identity.key | sed -n 's/peer_id = \"\\(.*\\)\"/\\1/p'").strip()
        print(c["cn"], c["altnames"], c["issuer"])
        assert "ip4-${lib.replaceStrings ["."] ["-"] (ip "alice")}.${zone}" in c["altnames"], c
        assert f"{label6('${ip6 "alice"}')}.${zone}" in c["altnames"], c
        assert "Pebble" in c["issuer"], c
        alice.succeed(f"dig +short @${ip "server"} {c['cn']} TXT | grep -x '\"id={alice_id}\"'")
        alice.wait_for_open_port(4443)

    alice_name = "ip4-${lib.replaceStrings ["."] ["-"] (ip "alice")}.${zone}"
    alice_wss = f"/dns4/{alice_name}/tcp/4443/tls/ws/p2p/{alice_id}"

    with subtest("bob verifies alice's certificate and dials her over WSS"):
        bob.succeed(f"openssl s_client -connect {alice_name}:4443 -servername {alice_name} -CAfile ${root} -verify_return_error </dev/null 2>&1 | grep 'Verify return code: 0'")
        bob.succeed(f"nodetrust ping {alice_wss} --ca ${root}")

    with subtest("discovery between rust clients"):
        bob.systemctl("start nodetrust-client")
        bob.wait_until_succeeds("test -s /var/lib/nodetrust-client/cert.json", timeout=180)
        bob_id = bob.succeed("nodetrust pubkey --key /var/lib/nodetrust-client/identity.key | sed -n 's/peer_id = \"\\(.*\\)\"/\\1/p'").strip()
        bob.wait_until_succeeds(f"journalctl -u nodetrust-client | grep 'discovered peer' | grep {alice_id}", timeout=120)
        alice.wait_until_succeeds(f"journalctl -u nodetrust-client | grep 'discovered peer' | grep {bob_id}", timeout=120)
        # discovered peers are dialed over their announced WSS address (whoever discovers first dials)
        dialed = lambda m, peer: m.execute(f"journalctl -u nodetrust-client | grep connected | grep {peer} | grep -q tls/ws")[0] == 0
        retry(lambda _: dialed(bob, alice_id) or dialed(alice, bob_id), timeout_seconds=120)

    with subtest("js client: issuance and interop"):
        carol.systemctl("start nodetrust-js")
        carol.wait_until_succeeds("test -s /var/lib/nodetrust-js/cert.json", timeout=180)
        cc = cert(carol, "/var/lib/nodetrust-js/cert.json")
        assert "ip4-${lib.replaceStrings ["."] ["-"] (ip "carol")}.${zone}" in cc["altnames"], cc
        carol_id = carol.succeed("journalctl -u nodetrust-js | grep -o 'starting peer=[^ ]*' | head -1 | cut -d= -f2").strip()
        carol_wss = f"/dns4/ip4-${lib.replaceStrings ["."] ["-"] (ip "carol")}.${zone}/tcp/4445/tls/ws/p2p/{carol_id}"
        bob.succeed(f"nodetrust ping {carol_wss} --ca ${root}")  # rust dialer, js listener
        carol.succeed(f"NODE_EXTRA_CA_CERTS=${root} nodetrust-js ping {alice_wss}")  # js dialer, rust listener
        carol.wait_until_succeeds(f"journalctl -u nodetrust-js | grep 'discovered peer {alice_id}'", timeout=120)
        alice.wait_until_succeeds(f"journalctl -u nodetrust-client | grep 'discovered peer' | grep {carol_id}", timeout=120)

    with subtest("certificates renew in place"):
        served = lambda: alice.succeed(f"openssl s_client -connect {alice_name}:4443 -servername {alice_name} </dev/null 2>/dev/null | openssl x509 -noout -enddate").strip()
        served_before = served()
        before = cert(alice)["not_after_ms"]
        alice.wait_until_succeeds(f"test $(jq .not_after_ms /var/lib/nodetrust-client/cert.json) -gt {before}", timeout=400)
        # the listener serves the new certificate without a restart
        alice.wait_until_succeeds(f"test \"$(openssl s_client -connect {alice_name}:4443 -servername {alice_name} </dev/null 2>/dev/null | openssl x509 -noout -enddate)\" != '{served_before}'", timeout=30)
        assert alice.succeed("systemctl show -p NRestarts --value nodetrust-client").strip() == "0"
        bob.succeed(f"openssl s_client -connect {alice_name}:4443 -servername {alice_name} -CAfile ${root} -verify_return_error </dev/null 2>&1 | grep 'Verify return code: 0'")
        bob.succeed(f"nodetrust ping {alice_wss} --ca ${root}")
        before = cc["not_after_ms"]
        carol.wait_until_succeeds(f"test $(jq .not_after_ms /var/lib/nodetrust-js/cert.json) -gt {before}", timeout=400)
        bob.succeed(f"nodetrust ping {carol_wss} --ca ${root}")
  '';
}
