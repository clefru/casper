#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CASPER_STORE="${CASPER_STORE:-$SCRIPT_DIR/casper-store}"
NIX_BUILD="${NIX_BUILD:-$SCRIPT_DIR/nix/build/src/nix/nix-build}"
NIXPKGS="${NIXPKGS:-<nixpkgs>}"

echo "=== CASPER Bootstrap into $CASPER_STORE ==="

# 1. Stage 0 POSIX minimal-bootstrap (hex0-seed -> kaem)
echo "--- [1/2] Building stage0-posix minimal-bootstrap (hex0-seed -> kaem) ---"
"$NIX_BUILD" --store "$CASPER_STORE" --no-out-link -E "
  let
    pkgs = import $NIXPKGS {
      overlays = [ (import $SCRIPT_DIR/casper-overlay.nix) ];
    };
  in pkgs.minimal-bootstrap.kaem
"

# 2. Full Nixpkgs stdenv bootstrap (stage0 -> stage1 -> stage-xgcc -> stage2 -> stage3 -> stage4 -> stdenv -> hello)
echo "--- [2/2] Building full Nixpkgs stdenv bootstrap & GNU hello ---"
"$NIX_BUILD" --store "$CASPER_STORE" --no-out-link -E "
  let
    pkgs = import $NIXPKGS {
      overlays = [ (import $SCRIPT_DIR/casper-overlay.nix) ];
    };
  in [ pkgs.stdenv pkgs.hello ]
"

echo "=== Bootstrap complete! Verifying PathRewrites in $CASPER_STORE/nix/var/nix/db/db.sqlite ==="
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$CASPER_STORE/nix/var/nix/db/db.sqlite" \
        "SELECT COUNT(*) AS total_relocated_outputs, COUNT(DISTINCT outputPath) AS unique_ca_outputs FROM PathRewrites;"
fi
