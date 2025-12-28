{
  description = "Waterfall service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      # Define the base NixOS module
      waterfallBaseModule =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        with lib;
        let
          cfg = config.services.waterfall;
        in
        {
          # Options definition
          options.services.waterfall = {
            enable = mkEnableOption "waterfall service";

            package = mkOption {
              type = types.package;
              default = pkgs.bun;
              defaultText = literalExpression "pkgs.bun";
              description = "The package to use for the waterfall service.";
            };

            port = mkOption {
              type = types.port;
              default = 34007;
              description = "Port on which the waterfall service listens.";
            };

            databasePath = mkOption {
              type = types.str;
              default = "/var/lib/waterfall/tokens.db";
              description = ''
                Path to the database file.
                This path must be writable by the waterfall service user.
                By default, it points to a location under /var/lib which is writable.
              '';
            };
          };

          # Configuration (only evaluated when enabled)
          config = mkIf cfg.enable {
            users.users.waterfall = {
              description = "waterfall service user";
              group = "waterfall";
              isSystemUser = true;
            };

            users.groups.waterfall = { };

            systemd.tmpfiles.rules = [
              # Create the directory for the database with proper ownership
              "d '${dirOf cfg.databasePath}' 0755 waterfall waterfall - -"
              # Create the database file if it doesn't exist
              "f '${cfg.databasePath}' 0644 waterfall waterfall - -"
            ];

            systemd.services.waterfall = {
              description = "waterfall service";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              serviceConfig = {
                Type = "simple";
                User = "waterfall";
                Group = "waterfall";
                Restart = "always";
                ExecStart = "${cfg.package}/bin/waterfall";
                WorkingDirectory = "/var/lib/waterfall";
                Environment = [
                  "PORT=${toString cfg.port}"
                  "DATABASE_PATH=${cfg.databasePath}"
                ];
              };
            };

            # Only add to system packages when enabled
            environment.systemPackages = [ cfg.package ];
          };
        };

      # Define the enhanced module that uses the flake's package
      waterfallModule =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ waterfallBaseModule ];

          config = lib.mkIf config.services.waterfall.enable {
            services.waterfall.package = self.packages.${pkgs.system}.waterfall;
          };
        };
    in
    {
      # Export the NixOS modules
      nixosModules = {
        default = waterfallModule;
        waterfall = waterfallModule;
        base = waterfallBaseModule;
      };

      # Create packages for different systems
      packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
        system:
        let
          pkgs = import nixpkgs { inherit system; };

          # Create a Fixed Output Derivation for node_modules
          nodeModules = pkgs.stdenv.mkDerivation {
            pname = "waterfall-node_modules";
            version = "1.0.3";
            impureEnvVars = pkgs.lib.fetchers.proxyImpureEnvVars ++ [
              "GIT_PROXY_COMMAND"
              "SOCKS_SERVER"
            ];
            src = ./.;
            nativeBuildInputs = [ pkgs.bun ];
            dontConfigure = true;
            buildPhase = ''
              bun install --no-progress --frozen-lockfile --no-cache
              bun pm cache rm
            '';
            installPhase = ''
              mkdir -p $out/node_modules
              cp -R ./node_modules/. $out/node_modules/
            '';
            outputHash = "sha256-OOPJFInzwian73OsaauDlGO3LTAEAuAidKj+REeEFA8=";
            outputHashAlgo = "sha256";
            outputHashMode = "recursive";
          };
        in
        {
          waterfall = pkgs.stdenv.mkDerivation {
            pname = "waterfall";
            version = "1.0.3";

            src = ./.;

            nativeBuildInputs = [ pkgs.bun ];

            configurePhase = ''
              runHook preConfigure

              # Copy node_modules from FOD
              mkdir -p node_modules
              cp -R ${nodeModules}/node_modules/. ./node_modules/

              runHook postConfigure
            '';

            # Build the project targeting bun
            buildPhase = ''
              runHook preBuild

              mkdir -p dist
              bun build index.ts --minify --target bun --outfile dist/index.js

              runHook postBuild
            '';

            # Install the built script
            installPhase = ''
              runHook preInstall

              mkdir -p $out/lib/waterfall
              cp dist/index.js $out/lib/waterfall/index.js

              # Create a wrapper script
              mkdir -p $out/bin
              cat > $out/bin/waterfall << EOF
              #!${pkgs.runtimeShell}
              cd $out/lib/waterfall
              exec ${pkgs.bun}/bin/bun index.js "\$@"
              EOF
              chmod +x $out/bin/waterfall
              runHook postInstall
            '';

            meta = {
              description = "Waterfall service";
              homepage = "https://github.com/Sanfrag/waterfall";
              license = nixpkgs.lib.licenses.mit;
              maintainers = [ ];
              platforms = nixpkgs.lib.platforms.unix;
            };
          };
        }
      );
    };
}
