{
  description = "veto-rs - local verification gates (Rust)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        toolchain = fenix.packages.${system}.stable.toolchain;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            toolchain
            pkgs.pkg-config
            pkgs.openssl
            pkgs.git
            pkgs.just
          ];
          RUST_BACKTRACE = "1";
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "veto";
          version = "0.2.2";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };
      }
    );
}
