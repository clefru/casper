# CASPER Alternatives Considered (and Why They Were Discarded)

This document records the alternative design choices explored during the development of **CASPER (Content-Addressable Store via Partial-blinding and Embedded Relocation)** and explains why they were discarded in favor of the primary `NAR` $\to$ `NAR` stream relocation architecture described in [README.md](README.md).

---

## 1. In-Place Directory Relocation (`relocate.sh <target-dir> <old-self> <new-self>`) (Discarded / Used in Initial Prototype)

Before converging on the `NAR` $\to$ `NAR` stream transformer design ([README.md Section 2.2](README.md#22-relocatesh-as-a-nar-to-nar-stream-transformer-stdin-to-stdout)), the initial CASPER design and bootstrap prototype mutated `$out` in place on the filesystem via `relocate.sh <target-path> <old-self> <new-self>`:
```sh
/bin/sh "$out/nix-support/relocate.sh" <target-path> <old-self> <new-self>
```

- **Why Discarded in Favor of `NAR` $\to$ `NAR` ([README.md Section 2.2](README.md#22-relocatesh-as-a-nar-to-nar-stream-transformer-stdin-to-stdout))**:
  1. **Host-`root` vs. Sandbox-User Filesystem Races**: Mutating `$out` in place on the host filesystem requires `chown`/`chmod` dances between the host `root` daemon and the sandbox `buildUser`, opening TOCTOU symlink and hardlink races (see [security.md](security.md)) and leaking filesystem metadata (`mtime`/`inode`) between passes.
  2. **Redundant Disk I/O**: In-place mutation requires writing the blinded tree to disk, reading it back to hash it, and mutating it on disk a second time, whereas `NAR` $\to$ `NAR` pipes the blinded NAR stream directly into `HashSink(SHA256)` with zero disk writes.

### Prototype Default `$out/nix-support/relocate.sh` Script
```sh
#!/bin/sh
export LC_ALL=C
set -e
target="$1"
old="$2"
new="$3"
if [ -z "$old" ] || [ "$old" = "$new" ]; then
    exit 0
fi

# 1. Handle compressed .gz files if gzip and sed are available in PATH
if command -v gzip >/dev/null 2>&1 && command -v sed >/dev/null 2>&1 && command -v find >/dev/null 2>&1; then
    find "$target" -type f -name '*.gz' 2>/dev/null | while IFS= read -r f; do
        if gzip -dc "$f" 2>/dev/null | grep -q "$old" 2>/dev/null; then
            chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
            if gzip -dc "$f" 2>/dev/null | sed "s|$old|$new|g" | gzip -n > "$f.tmp" 2>/dev/null; then
                cat "$f.tmp" > "$f"
            fi
            rm -f "$f.tmp"
        fi
    done
fi

# 2. Rewrite regular files containing old hash in-place (preserving permissions)
if command -v find >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 && command -v sed >/dev/null 2>&1; then
    find "$target" -type f ! -name '*.gz' -exec grep -l "$old" {} + 2>/dev/null | while IFS= read -r f; do
        chmod u+w "$(dirname "$f")" "$f" 2>/dev/null || true
        if sed "s|$old|$new|g" "$f" > "$f.tmp" 2>/dev/null; then
            cat "$f.tmp" > "$f"
        fi
        rm -f "$f.tmp"
    done
fi

# 3. Rewrite symlinks whose target contains old hash
if command -v find >/dev/null 2>&1 && command -v readlink >/dev/null 2>&1 && command -v sed >/dev/null 2>&1; then
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
fi
```

### Prototype Hybrid Sandbox + In-Process C++ Execution Flow
Inside `UnixDerivationBuilderImpl` / `ChrootLinuxDerivationBuilder` and [`DerivationBuilderImpl::registerOutputs`](nix/src/libstore/build/derivation-builder-impl.cc#L604-L698):
1. The builder child process runs inside the sandbox (with `sandboxMountNamespace` and `sandboxUserNamespace` preserved by `ChrootLinuxDerivationBuilder` until `cleanupBuild()`).
2. In `registerOutputs()`, if the output is a directory, Nix ensures `$out/nix-support/relocate.sh` and `$out/nix-support/hash.sh` exist, recording `hasCustomRelocate = true` if the builder supplied its own `relocate.sh`.
3. Nix checks `bool needRelocateScript = hasCustomRelocate || hasGzFiles(actualPath);`:
   - Whenever the package provides a custom `relocate.sh` or contains `.gz` files, Nix enters the saved sandbox namespaces (`sandboxMountNamespace`/`sandboxUserNamespace`) as the build user to execute `$out/nix-support/relocate.sh`.
   - In all cases, Nix also runs its fast in-process C++ [`rewritePathInPlace`](nix/src/libstore/build/derivation-builder-impl.cc#L204-L243) on non-`.gz` regular files and symlinks.
4. The three-step blind-hash-relocate cycle proceeds as `<inputHash>-<name>` $\to$ `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-<name>` $\to$ `outHash = compressHash(hashPath(actualPath), 20)` $\to$ `<outHash>-<name>`, followed by `canonicalisePathMetaData` and `optimisePath`.

---

## 2. Separate `$out/nix-support/hash.sh` Script (Discarded)

- **Idea**: Alongside `$out/nix-support/relocate.sh`, include a second script `$out/nix-support/hash.sh` responsible for computing the output's content hash (and allowing post-build verification on installed paths):
  ```sh
  #!/bin/sh
  export LC_ALL=C
  set -e
  target="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
  base="${2:-$(basename -- "$target")}"
  name="${base#????????????????????????????????-}"
  blind="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-$name"

  tmpdir=$(mktemp -d)
  trap 'chmod -R u+w "$tmpdir" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
  cp -a "$target" "$tmpdir/$base"
  chmod -R u+w "$tmpdir/$base" 2>/dev/null || true
  "$target/nix-support/relocate.sh" "$tmpdir/$base" "$base" "$blind"
  "${NIX_HASH_BIN:-nix-hash}" --type sha256 --truncate --base32 "$tmpdir/$base"
  ```
  The original motivation for separating `hash.sh` from `relocate.sh` was two-fold:
  1. **One-Way Blinding of Non-Deterministic Output Artifacts**: Partially non-deterministic packages (e.g., man-page generators embedding the current build year `2026`, or compilers embedding build timestamps) could strip those non-deterministic fields on the temporary copy inside `hash.sh` before hashing, while `relocate.sh` only performed reversible store-path rewrites on the live output.
  2. **Standalone Post-Build Verification**: Running `$out/nix-support/hash.sh` on an installed `/nix/store/<output-hash>-<name>` reproduced `<output-hash>`.

- **Why Discarded**:
  1. **Opens the Hostile / Weak Hasher Security Hole (`echo <static-hash>`; see [security.md](security.md))**:
     - If a derivation can bundle a custom `$out/nix-support/hash.sh` and Nix trusts its output as `<output-hash>`, a broken or hostile derivation (`evil-glibc`) can decouple **the digest Nix uses for the store path** from **the actual bytes in `$out`**.
     - Specifically, `evil-glibc` can predict legitimate `glibc-2.40-224`'s hash (`19zs62pdr843wg6gdlrv42pi9xsk7gin`), write `echo "19zs62pdr843wg6gdlrv42pi9xsk7gin"` in `hash.sh`, and install a malicious `libc.so.6` directly into `/nix/store/19zs62pdr843wg6gdlrv42pi9xsk7gin-glibc-2.40-224`.
     - Even if defended by requiring custom `hash.sh` to be a symlink to an external store dependency whose closure hash $H_{\text{closure}}$ is cryptographically combined with $H_{\text{content}}$ ($\text{SHA256}(H_{\text{closure}} \parallel H_{\text{content}})$), eliminating `hash.sh` altogether removes the attack surface completely.
  2. **In-Place Normalization (`postInstall` / `postFixup`) Is Strictly Superior to Temporary-Copy Blinding**:
     - When `hash.sh` strips a non-deterministic build year or timestamp on a temporary copy, two builds from different dates get the same store hash even though their actual installed files in `/nix/store` still differ.
     - Normalizing non-deterministic build dates or timestamps **in-place** during the build (`postInstall` or `postFixup`) makes the actual installed files on disk genuinely deterministic and byte-for-byte identical across builds.
  3. **Relying Solely on `relocate.sh` + Built-In C++ SHA-256 NAR Hashing Closes the Weak-Hasher Hole by Construction**:
     - When Nix relies **only** on `relocate.sh` and always hashes the blinded NAR stream directly in C++ (`HashSink(HashAlgorithm::SHA256)`), no untrusted script ever computes a digest, and `$out/nix-support/relocate.sh` is itself covered by the C++ SHA-256 NAR hash of `$out`.

---

## 3. Building in `/nix/build/<inputHash>-<name>` and Relocating to `/nix/store/<outHash>-<name>` (Discarded)

- **Idea**: Build derivations in `/nix/build/<inputHash>-<name>` instead of `/nix/store/<inputHash>-<name>`, then relocate to `/nix/store/<outHash>-<name>`. Since `"build"` and `"store"` both have 5 letters (`strlen("/nix/build/") == strlen("/nix/store/") == 11`), binary `RPATH`s and string tables keep the exact same byte length, while in-flight build outputs are cleanly separated from `/nix/store`.
- **Why Discarded**: In Nixpkgs, `binutils-wrapper` (`ld-wrapper`) enforces path purity via `badPath()` in `nix-support/utils.bash`:
  ```bash
  badPath() {
      local p=$1
      if [ "${p:0:1}" != / ]; then return 1; fi
      test \
          "$p" != "/dev/null" -a \
          "${p#"${NIX_STORE}"}"     = "$p" -a \
          "${p#"${NIX_BUILD_TOP}"}" = "$p" -a \
          "${p#/tmp}"               = "$p" -a \
          ...
  }
  ```
  `badPath()` only whitelists paths starting with `$NIX_STORE` (`/nix/store`), `$NIX_BUILD_TOP` (`/build`), or `/tmp` / `$TMPDIR`.
  - When `stdenv`'s `setup` adds `-rpath $out/lib` to `NIX_LDFLAGS` (`_addRpathPrefix "$out"`), an `$out` under `/nix/build/...` does not match `$NIX_STORE` (`/nix/store`) or `$NIX_BUILD_TOP` (`/build`).
  - As a result, unmodified Nixpkgs `ld-wrapper` treats `/nix/build/<inputHash>-<name>/lib` as an impure host path (like `/usr/lib`), stripping `-rpath $out/lib` from ELF binaries and aborting the link (`impure path '/nix/build/...' used in link`) whenever a full path `$out/lib/libfoo.so` is passed on the linker command line.
  - Building in `/nix/store/<inputHash>-<name>` inside the sandbox remains 100% compatible with unmodified Nixpkgs `stdenv` and `ld-wrapper`.

---

## 4. Hidden `.`-Prefixed Build Directory (`/nix/store/.<inputHash>-<name>`) + Store Symlinks (Discarded)

- **Idea**: Build in `/nix/store/.<inputHash>-<name>`, rename to `/nix/store/<outHash>-<name>` after the build, and place a symlink `.abcdef-foo -> fahxx11-foo` so self-references and downstream dependencies resolve through the symlink without rewriting.
- **Why Discarded**:
  1. Adding a leading `.` makes the build path 1 byte longer than the final path (`33` vs `32` chars before `-<name>`), preventing safe in-place binary rewriting of ELF string tables.
  2. By rewriting self-references via `$out/nix-support/relocate.sh` and rewriting downstream builder arguments/environment variables before building, store symlinks and `.` prefixes are unnecessary.
