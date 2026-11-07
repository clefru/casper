# CASPER (Content-Addressable Store via Partial-blinding and Embedded Relocation)
# Lightweight Nixpkgs Overlay
#
# Usage:
#   import <nixpkgs> { overlays = [ (import ./casper-overlay.nix) ]; }
#
# Builds a standalone, statically-linked streaming NAR -> NAR relocator
# (`casper-relocate`, including deterministic .gz decompression/rewriting/recompression)
# with zero runtime store references (`allowedReferences = []`), symlinks
# `$output/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate`,
# and automatically permits `casper-relocate` in `allowedReferences` / `allowedRequisites`.

final: prev:
let
  bootPkgs = prev.stdenv.__bootPackages or prev;

  casper-relocate = prev.stdenv.mkDerivation {
    pname = "casper-relocate";
    version = "1.0.0";
    dontUnpack = true;
    buildInputs = [
      prev.stdenv.cc.libc.static
      bootPkgs.zlib.dev
      bootPkgs.zlib.static
    ];
    allowedReferences = [ ];
    buildPhase = ''
      mkdir -p "$out/bin"
      $CC -O2 -Wall -Wextra -static ${./casper-relocate.c} -lz -o "$out/bin/casper-relocate"
      strip -s "$out/bin/casper-relocate"
      sed -i 's|/nix/store/[0-9a-df-np-sv-z]\{32\}-|/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-|g' "$out/bin/casper-relocate"
    '';
    dontInstall = true;
    dontFixup = true;
  };

  extendRefChecks =
    old:
    let
      addRelocator = list: if list == null then null else list ++ [ casper-relocate ];
      patchCheckAttr =
        chk:
        chk
        // prev.lib.optionalAttrs (chk ? allowedReferences && chk.allowedReferences != null) {
          allowedReferences = addRelocator chk.allowedReferences;
        }
        // prev.lib.optionalAttrs (chk ? allowedRequisites && chk.allowedRequisites != null) {
          allowedRequisites = addRelocator chk.allowedRequisites;
        };
    in
    prev.lib.optionalAttrs (old ? allowedReferences && old.allowedReferences != null) {
      allowedReferences = addRelocator old.allowedReferences;
    }
    // prev.lib.optionalAttrs (old ? allowedRequisites && old.allowedRequisites != null) {
      allowedRequisites = addRelocator old.allowedRequisites;
    }
    // prev.lib.optionalAttrs (old ? outputChecks && builtins.isAttrs old.outputChecks) {
      outputChecks = prev.lib.mapAttrs (_: patchCheckAttr) old.outputChecks;
    };

  /* Low-level helper that attaches a symlink
     `$output/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate`
     (or a custom NAR -> NAR script when `relocateStream` / `relocateExtra` is specified)
     and updates `allowedReferences` / `allowedRequisites` in the overlay. */
  withCasper =
    {
      relocateExtra ? "",
      relocateStream ? "",
    }:
    pkg:
    let
      isDefaultSymlink = relocateStream == "" && relocateExtra == "";
      hookScript =
        if isDefaultSymlink then
          ''
            for _casper_out in ''${outputs:-out}; do
              eval "_casper_dir=\$$_casper_out"
              if [ -n "$_casper_dir" ] && [ -d "$_casper_dir" ] && [ ! -e "$_casper_dir/nix-support/relocate.sh" ]; then
                if [ -n "$(find "$_casper_dir" -type f -name '*.gz' -print -quit 2>/dev/null)" ]; then
                  mkdir -p "$_casper_dir/nix-support"
                  ln -s ${casper-relocate}/bin/casper-relocate "$_casper_dir/nix-support/relocate.sh"
                fi
              fi
            done
          ''
        else
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
                        chmod u+w "$(dirname "$l")" "$l" 2>/dev/null || true
                        ln -snf "$newlnk" "$l" 2>/dev/null || true
                        ;;
                esac
            done

            # 4. Package-specific CASPER relocation rules
            ${relocateExtra}

            nix-store --dump "$target"
            CASPER_RELOCATE_EOF
              chmod +x "$out/nix-support/relocate.sh"
            fi
          '';

      transformAttrs =
        old:
        {
          nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ casper-relocate ];
          postFixup = (old.postFixup or "") + "\n" + hookScript;
        }
        // extendRefChecks old;
    in
    if pkg ? overrideAttrs then
      pkg.overrideAttrs transformAttrs
    else
      prev.lib.overrideDerivation pkg transformAttrs;

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
  inherit casper-relocate;

  stdenv =
    if prev.lib.hasPrefix "bootstrap-" prev.stdenv.name then
      prev.stdenv
    else
      prev.stdenv
      // {
        mkDerivation = args: withCasper { } (prev.stdenv.mkDerivation args);
      };

  casper = {
    inherit casper-relocate withCasper casperRelocateSnippets;
  };
}
