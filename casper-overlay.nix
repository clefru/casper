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
     builders) via overrideAttrs when available, falling back to overrideDerivation. */
  withCasper =
    {
      relocateExtra ? "",
      hashExtra ? "",
    }:
    pkg:
    let
      hookScript =
        ''
          if [ -d "$out" ]; then
            mkdir -p "$out/nix-support"
        ''
        + prev.lib.optionalString (relocateExtra != "") ''
            cat << 'CASPER_RELOCATE_EOF' > "$out/nix-support/relocate.sh"
          #!/bin/sh
          export LC_ALL=C
          target="$1"
          old="$2"
          new="$3"
          if [ -z "$target" ] || [ -z "$old" ] || [ -z "$new" ] || [ "$old" = "$new" ]; then
              exit 0
          fi

          # 1. Decompress, rewrite, and deterministically recompress gzip files containing old hash
          find "$target" -type f -name '*.gz' 2>/dev/null | while IFS= read -r f; do
              if gzip -dc "$f" 2>/dev/null | grep -q "$old" 2>/dev/null; then
                  chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
                  if gzip -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | gzip -n > "$f.tmp"; then
                      cat "$f.tmp" > "$f"
                  fi
                  rm -f "$f.tmp"
              fi
          done

          # 2. Rewrite regular files containing old hash in-place (preserving permissions)
          find "$target" -type f ! -name '*.gz' -exec grep -l "$old" {} + 2>/dev/null | while IFS= read -r f; do
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
          CASPER_RELOCATE_EOF
            chmod +x "$out/nix-support/relocate.sh"
        ''
        + prev.lib.optionalString (hashExtra != "") ''
            cat << 'CASPER_HASH_EOF' > "$out/nix-support/hash.sh"
          #!/bin/sh
          export LC_ALL=C
          set -e
          if [ "$1" = "--blind-in-place" ]; then
              target="$2"
              old_self="$3"
              blind_self="$4"
              "$target/nix-support/relocate.sh" "$target" "$old_self" "$blind_self"
              ${hashExtra}
              exit 0
          fi

          target="''${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
          base="''${2:-$(basename -- "$target")}"
          name="''${base#????????????????????????????????-}"
          blind="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-$name"

          tmpdir=$(mktemp -d)
          trap 'chmod -R u+w "$tmpdir" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
          cp -a "$target" "$tmpdir/$base"
          chmod -R u+w "$tmpdir/$base" 2>/dev/null || true
          "$target/nix-support/relocate.sh" "$tmpdir/$base" "$base" "$blind"
          (
              target="$tmpdir/$base"
              ${hashExtra}
          )
          "''${NIX_HASH_BIN:-nix-hash}" --type sha256 --truncate --base32 "$tmpdir/$base"
          CASPER_HASH_EOF
            chmod +x "$out/nix-support/hash.sh"
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
