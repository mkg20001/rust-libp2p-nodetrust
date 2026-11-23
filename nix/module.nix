# NixOS module: services.nodetrust.{dns,proof,issue,client}
{ config, lib, pkgs, ... }:

let
  cfg = config.services.nodetrust;
  toml = pkgs.formats.toml { };

  roles = {
    dns = "DNS server (zone + /dns-01 for issue servers)";
    proof = "proof server (signs observed TCP addresses)";
    issue = "issue server (ACME certificates for proven addresses)";
    client = "client (certificate, WSS listener, discovery)";
  };

  roleOptions = role: description: {
    enable = lib.mkEnableOption "nodetrust ${description}";

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        Contents of the `[${role}]` section (see `examples/${role}.toml`).
        `state_dir` and key paths are filled in by the module.
      '';
    };

    listen = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/ip4/0.0.0.0/tcp/25893" "/ip6/::/tcp/25893" ];
      description = "libp2p listen multiaddrs.";
    };

    relay = lib.mkOption {
      type = lib.types.bool;
      default = role == "dns" || role == "issue";
      description = "Serve as circuit relay (hop) for other peers.";
    };

    identityFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        libp2p identity key (protobuf, from `nodetrust keygen`). Loaded via systemd credentials.
        If null, a key is generated in the state directory on first start.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP ports of `listen` (and DNS / WSS ports where applicable).";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra command line arguments.";
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = { RUST_LOG = "debug"; SENTRY_DSN = "https://…"; };
      description = "Environment variables.";
    };
  };

  portOf = addr: let m = builtins.match ".*/(tcp|udp)/([0-9]+).*" addr; in
    if m == null then null else lib.toInt (builtins.elemAt m 1);
  tcpPorts = addrs: lib.filter (p: p != null && p != 0) (map portOf addrs);
  # "0.0.0.0:53" / "[::]:53"
  dnsPorts = lib.unique (map (a: lib.toInt (lib.last (lib.splitString ":" a))) (cfg.dns.settings.listen or [ ]));

  unit = role: let
    rc = cfg.${role};
    state = "/var/lib/nodetrust-${role}";
    keyPath = if rc.identityFile == null then "${state}/identity.key" else "%d/identity";
    section = rc.settings
      // lib.optionalAttrs (role == "issue" || role == "client") { state_dir = rc.settings.state_dir or state; }
      // lib.optionalAttrs (role == "proof") { key_file = "%d/proof"; };
    file = toml.generate "nodetrust-${role}.toml" {
      node = { key_file = keyPath; listen = rc.listen; relay = rc.relay; };
      ${role} = section;
    };
  in {
    description = "nodetrust ${roles.${role}}";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    environment = rc.environment;
    serviceConfig = {
      # %d (credentials dir) is only known at runtime: substitute it into the config there
      ExecStart = pkgs.writeShellScript "nodetrust-${role}" ''
        set -eu
        sed "s|%d|''${CREDENTIALS_DIRECTORY:-}|g" ${file} > "$RUNTIME_DIRECTORY/config.toml"
        exec ${lib.getExe cfg.package} ${role} --config "$RUNTIME_DIRECTORY/config.toml" ${lib.escapeShellArgs rc.extraArgs}
      '';
      DynamicUser = true;
      StateDirectory = "nodetrust-${role}";
      RuntimeDirectory = "nodetrust-${role}";
      WorkingDirectory = state;
      LoadCredential =
        lib.optional (rc.identityFile != null) "identity:${rc.identityFile}"
        ++ lib.optional (role == "proof") "proof:${cfg.proof.keyFile}"
        ++ lib.optional (role == "issue" && cfg.issue.acmeCaFile != null) "acme-ca:${cfg.issue.acmeCaFile}";
      Restart = "always";
      RestartSec = 5;

      AmbientCapabilities = lib.optional (role == "dns") "CAP_NET_BIND_SERVICE";
      CapabilityBoundingSet = lib.optional (role == "dns") "CAP_NET_BIND_SERVICE";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" ];
      UMask = "0077";
    };
  };
in
{
  options.services.nodetrust = {
    package = lib.mkOption {
      type = lib.types.package;
      description = "nodetrust package.";
    };
  } // lib.mapAttrs roleOptions roles // {
    proof = roleOptions "proof" roles.proof // {
      keyFile = lib.mkOption {
        type = lib.types.path;
        description = "Proof signing key (protobuf, from `nodetrust keygen`). Its public key goes into `issue.settings.proof_keys`.";
      };
    };
    issue = roleOptions "issue" roles.issue // {
      acmeCaFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Root CA (PEM) of the ACME server's HTTPS endpoint, e.g. Pebble's. Sets `ca_file`.";
      };
    };
  };

  config = lib.mkMerge (lib.mapAttrsToList (role: _: lib.mkIf cfg.${role}.enable {
    systemd.services."nodetrust-${role}" = unit role;

    services.nodetrust.issue.settings = lib.mkIf (role == "issue" && cfg.issue.acmeCaFile != null) {
      ca_file = "%d/acme-ca";
    };

    networking.firewall = lib.mkIf cfg.${role}.openFirewall {
      allowedTCPPorts = tcpPorts cfg.${role}.listen
        ++ lib.optionals (role == "dns") dnsPorts
        ++ lib.optionals (role == "client") (tcpPorts [ (cfg.client.settings.wss_listen or "") ]);
      allowedUDPPorts = lib.optionals (role == "dns") dnsPorts;
    };
  }) roles);
}
