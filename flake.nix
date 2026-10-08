{
  description = "SOPS-encrypted Kubernetes secrets for the Seattle cluster";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # The CLI. patchShebangs pins the babashka it was built against, and the
      # wrapper supplies the two commands the script shells out to.
      mkCli = pkgs: pkgs.stdenvNoCC.mkDerivation {
        pname = "seattle-secret";
        version = "2.0.0";
        src = ./scripts/seattle-secret.clj;
        dontUnpack = true;
        nativeBuildInputs = [ pkgs.makeWrapper pkgs.babashka ];
        installPhase = ''
          install -Dm755 $src $out/bin/seattle-secret
          patchShebangs $out/bin/seattle-secret
          wrapProgram $out/bin/seattle-secret \
            --prefix PATH : ${pkgs.lib.makeBinPath (with pkgs; [
              sops
              git
            ])}
        '';
        meta = {
          description = "Create and update SOPS-encrypted secrets for the Seattle cluster";
          mainProgram = "seattle-secret";
        };
      };
    in
    {
      packages = forAllSystems (pkgs: rec {
        seattle-secret = mkCli pkgs;
        default = seattle-secret;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (mkCli pkgs)
            pkgs.babashka # to hack on the script itself
            pkgs.sops # for `sops edit` and anything the CLI does not cover
            pkgs.age # age-keygen, and inspecting recipients
          ];

          shellHook = ''
            echo "seattle secrets -- run 'seattle-secret --help' for usage"
            if [ -z "''${SOPS_AGE_KEY_FILE:-}" ] && [ -z "''${SOPS_AGE_KEY:-}" ]; then
              echo "note: no age identity configured; you can add secrets but not read them back."
            fi
          '';
        };
      });

      # `nix flake check` lints the script.
      checks = forAllSystems (pkgs: {
        clj-kondo = pkgs.runCommand "clj-kondo-seattle-secret"
          { nativeBuildInputs = [ pkgs.clj-kondo ]; }
          ''
            clj-kondo --lint ${./scripts/seattle-secret.clj}
            touch $out
          '';
      });
    };
}
