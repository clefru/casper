# CASPER (Content-Addressable Store via Partial-blinding and Embedded Relocation)
# Lightweight Nixpkgs Overlay
#
# Usage:
#   import <nixpkgs> { overlays = [ (import ./casper-overlay.nix) ]; }
#
# Note: Standard packages (ELF binaries, shared/static libraries, shell/script
# wrappers, pkg-config files, and .gz man/info pages) are handled automatically
# by CASPER's C++ DerivationBuilder without needing any overlay entries.
# This overlay provides helpers and overrides for packages with custom archive
# formats, checksum manifests, or non-deterministic build metadata.

final: prev:
let
  /* Low-level helper that works on any derivation (even non-stdenv.mkDerivation
     builders) via overrideAttrs when available, falling back to overrideDerivation.
     Generates a NAR -> NAR (stdin -> stdout) `$out/nix-support/relocate.sh <old> <new>`. */
  withCasper =
    {
      relocateExtra ? "",
      relocateStream ? "",
    }:
    pkg:
    let
      hookScript =
        ''
          if [ -d "$out" ]; then
            mkdir -p "$out/nix-support"
        ''
        + prev.lib.optionalString (relocateStream != "") ''
            cat << 'CASPER_RELOCATE_EOF' > "$out/nix-support/relocate.sh"
          #!/bin/sh
          export LC_ALL=C
          set -e
          old="$1"
          new="$2"
          if [ -z "$old" ] || [ -z "$new" ] || [ "$old" = "$new" ]; then
              cat
              exit 0
          fi
          ${relocateStream}
          CASPER_RELOCATE_EOF
            chmod +x "$out/nix-support/relocate.sh"
        ''
        + prev.lib.optionalString (relocateStream == "" && relocateExtra != "") ''
            cat << 'CASPER_RELOCATE_EOF' > "$out/nix-support/relocate.sh"
          #!/bin/sh
          export LC_ALL=C
          set -e
          old="$1"
          new="$2"
          if [ -z "$old" ] || [ -z "$new" ] || [ "$old" = "$new" ]; then
              cat
              exit 0
          fi

          workdir=$(mktemp -d)
          trap 'chmod -R u+w "$workdir" 2>/dev/null || true; rm -rf "$workdir"' EXIT
          target="$workdir/root"
          nix-store --restore "$target"
          chmod -R u+w "$target" 2>/dev/null || true

          # 1. Decompress, rewrite, and deterministically recompress gzip files containing old hash
          find "$target" -type f -name '*.gz' 2>/dev/null | while IFS= read -r f; do
              if gzip -dc "$f" 2>/dev/null | grep -qF "$old" 2>/dev/null; then
                  chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
                  if gzip -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | gzip -n > "$f.tmp"; then
                      cat "$f.tmp" > "$f"
                  fi
                  rm -f "$f.tmp"
              fi
          done

          # 2. Rewrite regular files containing old hash in-place (preserving permissions)
          find "$target" -type f ! -name '*.gz' -exec grep -lF "$old" {} + 2>/dev/null | while IFS= read -r f; do
              chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
              if sed "s|$old|$new|g" "$f" > "$f.tmp" 2>/dev/null; then
                  cat "$f.tmp" > "$f"
              fi
              rm -f "$f.tmp"
          done

          # 3. Rewrite symlinks whose target contains old hash
          find "$target" -type l 2>/dev/null | while IFS= read -r l; do
              lnk=$(readlink "$l" 2>/dev/null) || continue
              case "$lnk" in
                  *"$old"*)
                      newlnk=$(printf '%s\n' "$lnk" | sed "s|$old|$new|g")
                      chmod u+w "$(dirname "$l")" 2>/dev/null || true
                      ln -snf "$newlnk" "$l" 2>/dev/null || true
                      ;;
              esac
          done

          # 4. Package-specific CASPER relocation rules
          ${relocateExtra}

          nix-store --dump "$target"
          CASPER_RELOCATE_EOF
            chmod +x "$out/nix-support/relocate.sh"
        ''
        + ''
          fi
        '';
    in
    if pkg ? overrideAttrs then
      pkg.overrideAttrs (old: {
        postFixup = (old.postFixup or "") + "\n" + hookScript;
      })
    else
      prev.lib.overrideDerivation pkg (old: {
        postFixup = (old.postFixup or "") + "\n" + hookScript;
      });

  casperRelocateSnippets = {
    xz = ''
      find "$target" -type f -name '*.xz' 2>/dev/null | while IFS= read -r f; do
          if xz -dc "$f" 2>/dev/null | grep -q "$old" 2>/dev/null; then
              chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
              if xz -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | xz -z > "$f.tmp"; then
                  cat "$f.tmp" > "$f"
              fi
              rm -f "$f.tmp"
          fi
      done
    '';

    zst = ''
      find "$target" -type f -name '*.zst' 2>/dev/null | while IFS= read -r f; do
          if zstd -dc "$f" 2>/dev/null | grep -q "$old" 2>/dev/null; then
              chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
              if zstd -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | zstd -q > "$f.tmp"; then
                  cat "$f.tmp" > "$f"
              fi
              rm -f "$f.tmp"
          fi
      done
    '';

    pythonRecord = ''
      find "$target" -type f -path '*.dist-info/RECORD' 2>/dev/null | while IFS= read -r rec; do
          chmod u+w "$(dirname "$rec")" "$rec" 2>/dev/null || true
          sed -i 's|,sha256=[^,]*,|,,|g' "$rec" 2>/dev/null || true
      done
    '';
  };
in
{
  casper = {
    inherit withCasper casperRelocateSnippets;
  };
}
