{ inputs, ... }:
{
  imports = [
    inputs.rust-flake.flakeModules.default
    inputs.rust-flake.flakeModules.nixpkgs
  ];
  perSystem =
    {
      self',
      pkgs,
      lib,
      ...
    }:
    {
      rust-project.crates."clientmailforward".crane.args = {
        buildInputs = lib.optionals pkgs.stdenv.isDarwin (
          with pkgs.darwin.apple_sdk.frameworks;
          [
            IOKit
          ]
        );
      };
      packages.default = self'.packages.clientmailforward;
    };
}
