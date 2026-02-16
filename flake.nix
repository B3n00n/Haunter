{
  description = "Haunter - ARP spoofing tool for network security research";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" ];
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          rust
          pkgs.pkg-config
          pkgs.libpcap
        ];

        RUST_BACKTRACE = 1;
      };
    };
}
