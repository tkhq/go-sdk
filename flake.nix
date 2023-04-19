{
  description = "tkcli devshell";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.11";
    #nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # localstack is broken right now (2023-01-25) in unstable, due to a missing dependency
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        tkgenerate = pkgs.writeScriptBin "generate" ''
          #!/bin/sh
          swagger generate client -f https://raw.githubusercontent.com/tkhq/sdk/main/packages/http/src/__generated__/services/coordinator/public/v1/public_api.swagger.json -t pkg/api;
        '';

        tklint = pkgs.writeScriptBin "lint" ''
          #!/bin/sh
          ${pkgs.gofumpt}/bin/gofumpt -w . ./examples/ ./pkg/*
          ${pkgs.golangci-lint}/bin/golangci-lint run ./...
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            envsubst
            gofumpt
            golangci-lint
            go
            go-swagger
            go-tools
            tkgenerate
            tklint
          ];
        };
      });
}
