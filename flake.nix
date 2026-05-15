{
  description = "vuln-scanner — multi-phase LLM-powered vulnerability scanner over git repos";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;
        vuln-scanner = python.pkgs.buildPythonApplication {
          pname = "vuln-scanner";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [python.pkgs.hatchling];
          dependencies = [python.pkgs.rich];
        };
      in {
        packages.default = vuln-scanner;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python312
            uv
            ruff
            pyright
          ];

          shellHook = ''
            if [ ! -d .venv ]; then
              uv venv
            fi
            source .venv/bin/activate
            uv sync 2>/dev/null
          '';
        };
      }
    );
}
