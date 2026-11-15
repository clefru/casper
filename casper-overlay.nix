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

  casper-relocate =
    if
      (prev.stdenv.hostPlatform != prev.stdenv.buildPlatform || prev.stdenv.hostPlatform.isStatic)
      && (prev.buildPackages ? casper-relocate)
    then
      prev.buildPackages.casper-relocate
    else
      prev.stdenv.mkDerivation {
        pname = "casper-relocate";
        version = "1.0.0";
        dontUnpack = true;
        buildInputs = [
          (prev.stdenv.cc.libc.static or prev.stdenv.cc.libc)
          (bootPkgs.zlib.dev or bootPkgs.zlib)
          (bootPkgs.zlib.static or bootPkgs.zlib)
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
    relocatorDrv: old:
    let
      addRelocator = list: if list == null then null else list ++ [ relocatorDrv ];
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
     `$output/nix-support/relocate.sh -> ${relocatorDrv}/bin/casper-relocate`
     (always a symlink to a standalone derivation so its store-path hash serves
     as the cryptographic blinding target) and updates `allowedReferences` / `allowedRequisites`. */
  withCasper =
    {
      relocateExtra ? "",
      relocateStream ? "",
    }:
    pkg:
    let
      isDefaultSymlink = relocateStream == "" && relocateExtra == "";
      customRelocator = prev.stdenv.mkDerivation {
        name = "casper-relocate-${pkg.pname or pkg.name or "custom"}";
        dontUnpack = true;
        buildPhase =
          ''
            mkdir -p "$out/bin"
          ''
          + prev.lib.optionalString (relocateStream != "") ''
            cat << 'CASPER_RELOCATE_EOF' > "$out/bin/casper-relocate"
            #!/bin/sh
            export LC_ALL=C
            set -e
            has_scan_fd=0
            if { true >&3; } 2>/dev/null; then
                has_scan_fd=1
            fi
            no_rewrite=1
            case "''${1:-}" in
                *:*)
                    for _pair in "$@"; do
                        _o="''${_pair%%:*}"
                        _n="''${_pair#*:}"
                        if [ -n "$_o" ] && [ "$_o" != "$_n" ]; then
                            no_rewrite=0
                            break
                        fi
                    done
                    old="''${1%%:*}"
                    new="''${1#*:}"
                    ;;
                *)
                    old="''${1:-}"
                    new="''${2:-}"
                    if [ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$new" ]; then
                        no_rewrite=0
                    fi
                    ;;
            esac
            if [ "$no_rewrite" = 1 ] && [ "$has_scan_fd" = 0 ]; then
                cat
                exit 0
            fi
            ${relocateStream}
            CASPER_RELOCATE_EOF
            chmod +x "$out/bin/casper-relocate"
          ''
          + prev.lib.optionalString (relocateStream == "" && relocateExtra != "") ''
            mkdir -p "$out/libexec"
            cp ${casper-relocate}/bin/casper-relocate "$out/libexec/casper-relocate"
            chmod +x "$out/libexec/casper-relocate"
            cat << 'CASPER_RELOCATE_EOF' > "$out/bin/casper-relocate"
            #!/bin/sh
            export LC_ALL=C
            set -e
            self_exec="$0"
            if [ -L "$self_exec" ]; then
                self_exec=$(readlink "$self_exec")
            fi
            base_reloc="$(dirname "$self_exec")/../libexec/casper-relocate"

            has_scan_fd=0
            if { true >&3; } 2>/dev/null; then
                has_scan_fd=1
            fi

            no_rewrite=1
            case "''${1:-}" in
                *:*)
                    for _pair in "$@"; do
                        _o="''${_pair%%:*}"
                        _n="''${_pair#*:}"
                        if [ -n "$_o" ] && [ "$_o" != "$_n" ]; then
                            no_rewrite=0
                            break
                        fi
                    done
                    ;;
                *)
                    if [ -n "''${1:-}" ] && [ -n "''${2:-}" ] && [ "$1" != "$2" ]; then
                        no_rewrite=0
                    fi
                    ;;
            esac

            if [ "$no_rewrite" = 1 ] && [ "$has_scan_fd" = 0 ]; then
                cat
                exit 0
            fi

            workdir=$(mktemp -d)
            trap 'chmod -R u+w "$workdir" 2>/dev/null || true; rm -rf "$workdir"' EXIT
            target="$workdir/root"

            # 1. Stream through C casper-relocate (handles .gz + FD 3, regular files, symlinks, filenames)
            "$base_reloc" "$@" > "$workdir/reloc.nar"
            nix-store --restore "$target" < "$workdir/reloc.nar"
            rm -f "$workdir/reloc.nar"
            chmod -R u+w "$target" 2>/dev/null || true

            # 2. Package-specific CASPER relocation rules
            run_extra() {
                ${relocateExtra}
            }

            if [ "$no_rewrite" = 1 ]; then
                old=""
                new=""
                run_extra
            else
                case "''${1:-}" in
                    *:*)
                        _total=0
                        for _pair in "$@"; do
                            _o="''${_pair%%:*}"
                            _n="''${_pair#*:}"
                            if [ -n "$_o" ] && [ "$_o" != "$_n" ]; then
                                _total=$((_total + 1))
                            fi
                        done
                        _idx=0
                        _orig_scan="$has_scan_fd"
                        for _pair in "$@"; do
                            old="''${_pair%%:*}"
                            new="''${_pair#*:}"
                            if [ -n "$old" ] && [ "$old" != "$new" ]; then
                                _idx=$((_idx + 1))
                                if [ "$_idx" -eq "$_total" ]; then
                                    has_scan_fd="$_orig_scan"
                                else
                                    has_scan_fd=0
                                fi
                                run_extra
                            fi
                        done
                        ;;
                    *)
                        old="$1"
                        new="$2"
                        run_extra
                        ;;
                esac
            fi

            nix-store --dump "$target"
            CASPER_RELOCATE_EOF
            chmod +x "$out/bin/casper-relocate"
          '';
        dontInstall = true;
        dontFixup = true;
      };

      relocatorDrv = if isDefaultSymlink then casper-relocate else customRelocator;

      hookScript =
        if isDefaultSymlink then
          ''
            if [ -n "''${__structuredAttrs:-}" ]; then
              _casper_outputs="''${!outputs[*]}"
            else
              _casper_outputs="''${outputs:-out}"
            fi
            for _casper_out in $_casper_outputs; do
              if [ -n "''${__structuredAttrs:-}" ]; then
                _casper_dir="''${outputs[$_casper_out]}"
              else
                eval "_casper_dir=\''${$_casper_out:-}"
              fi
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
            if [ -n "''${__structuredAttrs:-}" ]; then
              _casper_outputs="''${!outputs[*]}"
            else
              _casper_outputs="''${outputs:-out}"
            fi
            for _casper_out in $_casper_outputs; do
              if [ -n "''${__structuredAttrs:-}" ]; then
                _casper_dir="''${outputs[$_casper_out]}"
              else
                eval "_casper_dir=\''${$_casper_out:-}"
              fi
              if [ -n "$_casper_dir" ] && [ -d "$_casper_dir" ] && [ ! -e "$_casper_dir/nix-support/relocate.sh" ]; then
                mkdir -p "$_casper_dir/nix-support"
                ln -s ${customRelocator}/bin/casper-relocate "$_casper_dir/nix-support/relocate.sh"
              fi
            done
          '';

      transformAttrs =
        old:
        let
          oldNativeBuildInputs =
            if (old.nativeBuildInputs or null) == null then [ ] else old.nativeBuildInputs;
          oldPostFixup =
            if (old.postFixup or null) == null then "" else old.postFixup;
        in
        {
          nativeBuildInputs = oldNativeBuildInputs ++ [ relocatorDrv ];
          postFixup = oldPostFixup + "\n" + hookScript;
        }
        // extendRefChecks relocatorDrv old;
    in
    if pkg ? overrideAttrs then
      pkg.overrideAttrs transformAttrs
    else
      prev.lib.overrideDerivation pkg transformAttrs;

  casperRelocateSnippets = {
    xz = ''
      find "$target" -type f -name '*.xz' 2>/dev/null | while IFS= read -r f; do
          if [ "''${no_rewrite:-0}" = 0 ] && xz -dc "$f" 2>/dev/null | grep -qF "$old" 2>/dev/null; then
              chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
              if xz -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | xz -z > "$f.tmp"; then
                  cat "$f.tmp" > "$f"
              fi
              rm -f "$f.tmp"
          fi
          if [ "''${has_scan_fd:-0}" = 1 ]; then
              xz -dc "$f" >&3 2>/dev/null || true
              printf '\n' >&3 2>/dev/null || true
          fi
      done
    '';

    zst = ''
      find "$target" -type f -name '*.zst' 2>/dev/null | while IFS= read -r f; do
          if [ "''${no_rewrite:-0}" = 0 ] && zstd -dc "$f" 2>/dev/null | grep -qF "$old" 2>/dev/null; then
              chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
              if zstd -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | zstd -q > "$f.tmp"; then
                  cat "$f.tmp" > "$f"
              fi
              rm -f "$f.tmp"
          fi
          if [ "''${has_scan_fd:-0}" = 1 ]; then
              zstd -dc "$f" >&3 2>/dev/null || true
              printf '\n' >&3 2>/dev/null || true
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

  # In rootless user-namespace sandboxes, unmapped supplementary host GIDs appear in
  # getgroups() as overflowgid (65534), causing rsync's chgrp test to try `chgrp 65534`
  # and fail with EINVAL.
  rsync = prev.rsync.overrideAttrs (_: {
    doCheck = false;
  });

  # IANA tzcode's `now.ck` test uses wall-clock `./date +%s` (`CHECK_NOW_TIMESTAMP`),
  # which fails once wall-clock time passes a scheduled DST-abolition cutover (such as
  # 2026-11-01 in tzdata-2026f). Pin `CHECK_NOW_TIMESTAMP` to the `NEWS` file's mtime.
  tzdata = prev.tzdata.overrideAttrs (old: {
    checkFlags = (old.checkFlags or [ ]) ++ [ "CHECK_NOW_TIMESTAMP=$$(date -r NEWS +%s)" ];
  });

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
// prev.lib.optionalAttrs (prev ? vhost-device-vsock) {
  # `test_vsock_thread_vsock_backend` requires the host kernel module `vsock_loopback`
  # (`VMADDR_CID_LOCAL`), which may not be loaded on the build host.
  vhost-device-vsock = prev.vhost-device-vsock.overrideAttrs (old: {
    checkFlags = (old.checkFlags or [ ]) ++ [
      "--skip=vhu_vsock_thread::tests::test_vsock_thread_vsock_backend"
    ];
  });
}
