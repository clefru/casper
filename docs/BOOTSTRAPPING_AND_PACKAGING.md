# CASPER Nixpkgs Bootstrapping, Packaging Trade-offs & Verification

This document covers the packaging trade-offs for opaque file formats, the dual-location rebuild verification trick, the lightweight [`casper-overlay.nix`](../casper-overlay.nix) strategy, and the end-to-end Nixpkgs bootstrap results (`stage0-posix` and `stdenv`) for **CASPER (Content-Addressable Store via Partial-blinding and Embedded Relocation)** (see [README.md](../README.md), [DETAILS.md](DETAILS.md), [NIX_IMPLEMENTATION.md](NIX_IMPLEMENTATION.md), [SECURITY.md](SECURITY.md), and [ALTERNATIVES_CONSIDERED.md](ALTERNATIVES_CONSIDERED.md)).

---

## 1. Reflections, Packaging Trade-offs & Verification Tricks

### 1.1 The Packaging Drawback: Maintaining `relocate.sh` for Opaque Formats
- In CASPER, package maintainers have the added responsibility of thinking about `relocate.sh` during packaging.
- Plaintext files, symlinks, standard ELF binaries, and static `.a` archives are easy to spot with `grep` and are handled automatically by Nix's built-in `relocateNAR` or [`casper-relocate`](../casper-relocate.c).
- However, self-references buried inside compressed or encoded formats—such as `.gz` files (handled automatically by [`casper-relocate`](../casper-relocate.c)), `.xz`/`.zst` archives, `.zip`/`.jar`/`.whl` archives, SQLite databases, or custom binary caches—are invisible to a naive `grep`. Spotting and rewriting these references normally requires package-specific domain knowledge so the packager can extend `relocate.sh` to unpack, rewrite, and repack those files.

### 1.2 Trick for Deterministic Packages: Dual-Location Rebuild to Detect Incomplete `relocate.sh`
- For **fully deterministic packages** (packages that always produce the exact same output byte stream given identical inputs and build environment), we can automatically detect hidden, unrelocated self-references *without* needing prior knowledge of the package's file formats:
  1. **Build 1**: Build the package in its normal scratch location `/nix/store/<input-hash>-foo`, run `relocate.sh` to blind `/nix/store/<input-hash>-foo` $\to$ `/nix/store/<blind-hash>-foo`, and compute the blinded output hash $H_1$.
  2. **Build 2 (`-recheck`)**: Rebuild the exact same derivation into a different output location—for example, `/nix/store/<input-hash>-foo-recheck` (or an alternate scratch hash).
  3. Run `relocate.sh` on the second build to blind `/nix/store/<input-hash>-foo-recheck` $\to$ `/nix/store/<blind-hash>-foo`, and compute the blinded output hash $H_2$.
  4. **Compare $H_1$ vs. $H_2$**:
     - If `relocate.sh` caught **every** self-reference, both blinded trees will be byte-for-byte identical and $H_1 = H_2$.
     - If the build embedded `$out` inside an unhandled format (e.g., an `.xz` archive or binary cache that `relocate.sh` did not unpack), the `-recheck` suffix remains inside that file after `relocate.sh` runs, causing $H_1 \neq H_2$.
     - Comparing the two blinded trees immediately alerts the packager to the incomplete `relocate.sh` and pinpoints the exact file containing the hidden self-reference.

---

## 2. Nixpkgs Overlay Strategy (`casper-overlay.nix`)

### 2.1 Format-Agnostic Built-In `relocateNAR` + Symlinked `casper-relocate`
- **Format-Agnostic C++ Fallback (`relocateNAR`)**:
  - During the early `stdenv` bootstrap (`minimal-bootstrap` and `bootstrap-stage0` through `bootstrap-stage4`), derivations do not embed self-references in `.gz` files (0 outputs in `casper-store`'s bootstrap closure had direct self-references in `.gz` files), and early stages execute in a minimal environment before `glibc.static` and `zlib.static` are available.
  - Nix C++'s built-in [`relocateNAR`](../nix/src/libstore/build/derivation-builder-impl.cc#L108-L240) is strictly format-agnostic: it streams `NAR` $\to$ `NAR` in $O(1)$ memory for uncompressed files, symlinks, and directory entry names when no `$out/nix-support/relocate.sh` is present.
- **Standalone Gzip-Capable `casper-relocate` Binary & Direct Symlink in [`casper-overlay.nix`](../casper-overlay.nix)**:
  - Once `stdenv` reaches its final stage, [`casper-overlay.nix`](../casper-overlay.nix) builds [`casper-relocate`](../casper-relocate.c) as a standalone, statically-linked C binary (`-static -lz`, ~760 KB, with `allowedReferences = []` and zero runtime store dependencies) that streams `NAR` $\to$ `NAR` (`stdin` $\to$ `stdout`), rewriting uncompressed regular files, symlinks, directory entry names, and `.gz`-compressed files (`zlib` `15 + 16` gzip format with deterministic `mtime = 0, os = 3` headers).
  - For every derivation built with `stdenv.mkDerivation` (or wrapped with `withCasper`), [`casper-overlay.nix`](../casper-overlay.nix):
    1. Checks each directory output (`${!outputs[*]}` under `__structuredAttrs = true`, or `${outputs:-out}` otherwise) for `.gz` files (`find "$_casper_dir" -type f -name '*.gz' -print -quit`) and creates a direct symlink `$_casper_dir/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate` **only when `.gz` files are present**—allowing outputs without `.gz` files to use the fast in-process C++ `relocateNAR` with zero extra files or references.
    2. Automatically extends `allowedReferences`, `allowedRequisites`, and `outputChecks.<out>.{allowedReferences,allowedRequisites}` with `casper-relocate` via `extendRefChecks`.
  - When a package requires additional custom relocation rules (e.g., `.xz`/`.zst` archives or Python `RECORD` files), `withCasper { relocateExtra = "..."; }` builds a standalone custom relocator derivation (`casper-relocate-<name>`) and symlinks `$out/nix-support/relocate.sh -> ${customReloc}/bin/casper-relocate`:

```nix
final: prev:
let
  # Helper to build a custom NAR -> NAR relocator derivation and symlink it at $out/nix-support/relocate.sh
  withCasper = { relocateExtra ? "", relocateStream ? "" }: pkg:
    let
      customReloc = prev.stdenv.mkDerivation {
        name = "casper-relocate-${pkg.pname or pkg.name or "custom"}";
        dontUnpack = true;
        dontFixup = true;
        buildCommand = ''
          mkdir -p "$out/bin"
          cat << 'EOF' > "$out/bin/casper-relocate"
          #!/bin/sh
          set -e
          old="$1"
          new="$2"
          workdir=$(mktemp -d)
          trap 'chmod -R u+w "$workdir" 2>/dev/null || true; rm -rf "$workdir"' EXIT
          target="$workdir/root"
          nix-store --restore "$target" < <(
            ${casper-relocate}/bin/casper-relocate "$old" "$new"
          )
          chmod -R u+w "$target" 2>/dev/null || true
          ${relocateExtra}
          nix-store --dump "$target"
          EOF
          chmod +x "$out/bin/casper-relocate"
        '';
      };
    in pkg.overrideAttrs (old: {
      postFixup = (old.postFixup or "") + prev.lib.optionalString (relocateExtra != "") ''
        mkdir -p "$out/nix-support"
        ln -sfn ${customReloc}/bin/casper-relocate "$out/nix-support/relocate.sh"
      '';
    });
in {
  # Example 1: Python packages with PEP 376 RECORD files storing SHA-256 hashes of scripts
  python3 = prev.python3.override {
    packageOverrides = pyFinal: pyPrev:
      prev.lib.mapAttrs (name: pkg:
        withCasper {
          relocateExtra = ''
            # Strip SHA-256 digests in *.dist-info/RECORD after shebang/path relocation
            find "$target" -path "*.dist-info/RECORD" -exec sed -i 's|,sha256=[^,]*,|,,|g' {} +
          '';
        } pkg
      ) pyPrev;
  };

  # Example 2: Packages with .zst or .xz compressed assets containing self-references
  someZstPackage = withCasper {
    relocateExtra = ''
      find "$target" -type f -name "*.zst" | while IFS= read -r zf; do
        zstd -dc "$zf" | sed "s|$old|$new|g" | zstd -q > "$zf.casper-tmp"
        mv "$zf.casper-tmp" "$zf"
      done
    '';
  } prev.someZstPackage;
}
```

> [!TIP]
> Notice `cat << 'EOF'` uses `#!/bin/sh` rather than `${prev.runtimeShell}` (`#!/nix/store/...-bash/bin/bash`). This ensures the custom script does not introduce an unwanted runtime store dependency on `bash` for data-only or minimal-closure outputs.

---

## 3. Bootstrapping Strategies: Incremental vs. Full `stdenv` Bootstrap

### 3.1 Mode A: Incremental Bootstrap on Top of an Existing `/nix/store` (Fastest)
- You do **not** have to rebuild `stdenv` from stage 0 just to start using CASPER with `nixpkgs`:
  - `localStore.resolveInputPath(inputPath)` in [`local-store.cc`](../nix/src/libstore/local-store.cc#L1838-L1854) returns `inputPath` unchanged whenever a store path has no entry in the `PathRewrites` SQLite table.
  - Therefore, pre-existing store paths in `/nix/store` (or paths substituted from `cache.nixos.org`) act as fixed leaves, while every **newly built** derivation goes through CASPER's streaming `NAR` $\to$ `NAR` blinding, content-hashing, and relocation.

### 3.2 Mode B: Full End-to-End Source Bootstrap (`hex0` $\to$ `stdenv`)
When bootstrapping `nixpkgs` from scratch (`minimal-bootstrap` through `stdenvStages` 0–4 to final `stdenv`):
1. **Stage 0 (`minimal-bootstrap` from `hex0`, or `bootstrap-tools` on older releases)**:
   - On `nixpkgs-unstable` (`x86_64-linux`), `stdenv` boots **100% from source** starting from the 357-byte `hex0` seed (`stage0-posix` $\to$ `mes` $\to$ `tinycc` $\to$ `musl` $\to$ `gcc-4.6.4` $\to$ `gcc-10.4.0`) with zero prebuilt `bootstrap-tools` binary tarball; on older releases such as NixOS 25.11, Stage 0 unpacks `bootstrap-tools` via `busybox`. In both cases, early outputs are relocated in-process by C++ [`relocateNAR`](../nix/src/libstore/build/derivation-builder-impl.cc#L108-L240) without requiring any external tools in the sandbox.
2. **Static Libraries (`.a` Archives) Across Bootstrap Stages (`minimal-bootstrap` $\to$ `stage0` $\to$ `stage4` $\to$ `stdenv`)**:
   - Early TinyCC/musl and GCC/glibc bootstrap stages build static `.a` archives (`crt`, `libgetopt.a`, `libtcc1.a`, `libgcc.a`, `libc.a`).
   - Standard `ar` archives store each member's byte size as a fixed-width decimal ASCII header and do not store member checksums. Because `<inputHash>` (32 chars), `<blindHash>` (32 chars), and `<outHash>` (32 chars) have the exact same byte length, `RewritingSink` relocation inside `.a` archives preserves member sizes and symbol tables without needing `ranlib`—allowing identical static libraries compiled across distinct bootstrap stages to deduplicate to a single content-addressed store path.
3. **Ecosystem-Level Hooks for Full Nixpkgs Coverage**:
   - Rather than overriding individual packages one by one, most non-plaintext formats in `nixpkgs` belong to language/framework ecosystems where a single hook covers thousands of packages:
     - **Python (`buildPythonPackage`)**: `*.dist-info/RECORD` files list SHA-256 hashes of installed entry-point scripts; when `relocate.sh` rewrites `$out` inside an entry-point script, `RECORD` either needs its hash updated or stripped.
     - **Haskell (`ghc` / `cabal`)**: `package.conf.d/package.cache` is a binary cache of `.conf` files containing `$out` paths; `relocate.sh` for GHC package DBs can re-run `ghc-pkg recache` or rewrite the binary cache.
     - **Linux Kernel Modules (`linux`)**: `.ko.xz` or `.ko.zst` modules that embed `$out` firmware/module paths need `xz`/`zstd` decompression/recompression in `relocate.sh`.
     - **Java / JVM (`.jar` / `.zip`)**: Unpacking/repacking `.jar` files only when `grep` detects a self-reference inside the uncompressed stream.
     - **macOS (`darwin`)**: Mach-O binaries with ad-hoc code signatures invalidate their signature when rewriting the `LC_RPATH` load command, requiring `codesign -f -s -` in `relocate.sh` on Darwin.

---

## 4. Real-World Bootstrap Verification (`casper-store`)

[`bootstrap.sh`](../bootstrap.sh) was executed end-to-end against upstream `nixpkgs-unstable` into a clean `casper-store` using `./nix/build/src/nix/nix-build` and [`casper-overlay.nix`](../casper-overlay.nix):

- **Upstream Snapshot**: `NixOS/nixpkgs` `refs/heads/nixpkgs-unstable` commit [`2074cc672349f14240fb7ea90d509e0b643e9dd4`](https://github.com/NixOS/nixpkgs/commit/2074cc672349f14240fb7ea90d509e0b643e9dd4) (`2026-11-12T14:50:34Z`, tarball SHA-256 `1f7094d999ce8f424b5bc001e09a21605e7d9c5535ad8a5e46b3598b8b5235d4`).
- **100% Source-Based Bootstrap (`hex0` $\to$ `hello-2.12.3`)**: Built **480 derivations** producing **591 relocated derivation outputs** (`PathRewrites` rows in `casper-store/nix/var/nix/db/db.sqlite`) that converged to **537 unique content-addressed store paths** (**54 duplicate outputs eliminated** across **29 deduplication groups**):
  1. **`minimal-bootstrap` Compiler Chain from `hex0-1.9.1`**:
     - Built from the 357-byte `hex0-1.9.1` seed through `hex1`, `hex2`, `catm`, `M0`, `M2-1.9.1`, `blood-elf`, `M1`, `mescc-tools-1.9.1`, `kaem-1.9.1`, `nyacc-1.09.1`, `mes-0.27.1`, `tinycc-boot-mes`, `tinycc-musl`, `musl-1.2.6`, `binutils-2.47`, `gcc-4.6.4`, `gcc-cxx-4.6.4`, and `gcc-10.4.0`—with zero prebuilt `bootstrap-tools` binary tarball.
  2. **Nixpkgs `stdenv` Stages (`stage0` $\to$ `stage1` $\to$ `stage2` $\to$ `stage3` $\to$ `stage4` $\to$ `stdenv-linux` $\to$ `hello-2.12.3`)**:
     - Continued from `minimal-bootstrap` through `linux-headers-7.3`, `glibc-2.44`, `binutils-2.46`, `gcc-16.2.0`, `coreutils-9.12`, `bash-5.3p20`, `stdenv-linux`, and `hello-2.12.3` via the streaming `NAR` $\to$ `NAR` pipeline.

### 4.1 Key Bootstrap Milestones (`inputPath` $\to$ Content-Addressed `outputPath`)

| Stage / Milestone | Evaluation Input Path (`<inputHash>-<name>`) | Relocated Content-Addressed Path (`<outHash>-<name>`) |
| :--- | :--- | :--- |
| **`stage0-posix` (`hex1-1.9.1`)** | `/nix/store/p5v3r1q7p5jxl9b4z8r3qla5x0kppjlf-hex1-1.9.1` | `/nix/store/7f0rmzg1bb3n74fv2rwh7wvgp4sz9gds-hex1-1.9.1` |
| **`stage0-posix` (`M2-1.9.1`)** | `/nix/store/c933x2407ahyia5bd2z39109zsk2q2b7-M2-1.9.1` | `/nix/store/jwknzxfmc1l3bmm2drvjn3s09mjhr20w-M2-1.9.1` |
| **`stage0-posix` (`mescc-tools-1.9.1`)** | `/nix/store/53zd871rgpcvi7qmqkffxhzaiq0is7k4-mescc-tools-1.9.1` | `/nix/store/z2nvwx19zzivivvklxp62x3x50cg8gy2-mescc-tools-1.9.1` |
| **`stage0-posix` (`kaem-1.9.1`)** | `/nix/store/n3mfz1lj8rbz0cspkfrvxiy9h5hm0vzg-kaem-1.9.1` | `/nix/store/126ag9igipwpls7j044pndfyav61dirx-kaem-1.9.1` |
| **`minimal-bootstrap` (`mes-0.27.1`)** | `/nix/store/g090bwdzxw6dsk2i5mxg5mpi939kwc2l-mes-0.27.1` | `/nix/store/0q85hkwyq9cgqvaj9n16fqfxgjxbis51-mes-0.27.1` |
| **`minimal-bootstrap` (`tinycc-boot-mes`)** | `/nix/store/wdv8qidsgiljsi30145zip0i2q8f8f7f-tinycc-boot-mes-unstable-2024-07-07` | `/nix/store/b5m70sa2kp62wxisgq8ngfz838wqflq0-tinycc-boot-mes-unstable-2024-07-07` |
| **`minimal-bootstrap` (`tinycc-musl`)** | `/nix/store/pbs7i6imdnzbksfh2adfflicxj026kr2-tinycc-musl-unstable-2025-12-03` | `/nix/store/ai5m42zkn0mjxn4lj3sg6rpliazbv63c-tinycc-musl-unstable-2025-12-03` |
| **`minimal-bootstrap` (`musl-1.2.6`)** | `/nix/store/19sak883ism6cb7sa8552c07ami7csa0-musl-1.2.6` | `/nix/store/r62zywb0yfv81nwhp6xr85n0j0f2l02a-musl-1.2.6` |
| **`minimal-bootstrap` (`gcc-4.6.4`)** | `/nix/store/f4cfdyd3kl579xgqhbm175mw27rc83xk-gcc-4.6.4` | `/nix/store/abbr1xbyg3j0nv9nsx784mjmwkwgmga4-gcc-4.6.4` |
| **`minimal-bootstrap` (`gcc-10.4.0`)** | `/nix/store/nxwifn8x71rbvz4pzfk3wwvasm2pqsl7-gcc-10.4.0` | `/nix/store/firwvq07zbnlm6i0d8cxcq795mfc8lid-gcc-10.4.0` |
| **Stage 0 (`stdenv-linux`)** | `/nix/store/5m3z6j447d37c3vvl1lla8jz5lkwgrdk-bootstrap-stage0-stdenv-linux` | `/nix/store/1wq633v4a13w36x1s38cgnvpff4iqq74-bootstrap-stage0-stdenv-linux` |
| **Stage 1 (`stdenv-linux`)** | `/nix/store/74cg5ywm4snpwglnsj8zjfjlgn76gab1-bootstrap-stage1-stdenv-linux` | `/nix/store/7k1sxgphicqdnwszsai3qf7pwh667v2h-bootstrap-stage1-stdenv-linux` |
| **Stage 2 (`linux-headers-7.3`)** | `/nix/store/p1aci5ysxkc3zh02ydh11fwqpaqsq3c4-linux-headers-7.3` | `/nix/store/v6bvjjn9qmqh9in14d0iflfblxl2pi00-linux-headers-7.3` |
| **Stage 2 (`glibc-2.44`)** | `/nix/store/ifg63pi3mbvdx0dqpd80lnghjwaqpqiv-glibc-2.44` | `/nix/store/ir5iwv6k4hxfqws7cxwy69n39i9s0gbs-glibc-2.44` |
| **Stage 3 (`stdenv-linux`)** | `/nix/store/azdg9gndwjb9liisb585yxzg15c8wg65-bootstrap-stage3-stdenv-linux` | `/nix/store/7hp9b49rf8c8kb4szsijislfcsyc87i8-bootstrap-stage3-stdenv-linux` |
| **Stage 4 (`stdenv-linux`)** | `/nix/store/4d95cawixqkmi505bmvvizyp28p9zjfr-bootstrap-stage4-stdenv-linux` | `/nix/store/c4dihkcg7ai1fx16zz5wz9r8ny8vpdlp-bootstrap-stage4-stdenv-linux` |
| **Stage 4 (`gcc-16.2.0`)** | `/nix/store/rp1zq1p0rjfdg99rb2cfs14871y6cqaj-gcc-16.2.0` | `/nix/store/3zqg8qxx9ywh95ykhk44bkc9k5n8qvzl-gcc-16.2.0` |
| **Stage 4 (`coreutils-9.12`)** | `/nix/store/a50ml7za6h61m4mv4cdbvkl33c6sx5yn-coreutils-9.12` | `/nix/store/ykkhycflm4r7xbqcpfgym6mg0s8wi2by-coreutils-9.12` |
| **Stage 4 (`bash-5.3p20`)** | `/nix/store/hasnvc0j36gg6qrdsfcx7yivx3c2bpqr-bash-5.3p20` | `/nix/store/gs0xq5c4rqh3bigb7bxx4fc4php2nyw8-bash-5.3p20` |
| **Final `gcc-16.2.0`** | `/nix/store/8x94na5lhckj4p05hlb0l1jkzqgg7yg0-gcc-16.2.0` | `/nix/store/s6wa8hzcahyaafx71yin40jzmvjq4b4w-gcc-16.2.0` |
| **Final `stdenv-linux`** | `/nix/store/z2wyfgcxn7brfklv373fz0l9k8b5pwsg-stdenv-linux` | `/nix/store/gnmygfqjdj4glmc64xnx0j3s4yslz1dh-stdenv-linux` |
| **Final `hello-2.12.3`** | `/nix/store/2g1jryvsiljc69g8yi3sqzcj9cvwfqyy-hello-2.12.3` | `/nix/store/5q3rabjwwd2lanj8can9i0l2kk3yl5rp-hello-2.12.3` |

### 4.2 Cross-Stage Content-Addressed Deduplication (29 Output Groups Across `minimal-bootstrap` & Stages 0–4)
Querying `PathRewrites` in `casper-store/nix/var/nix/db/db.sqlite` showed **29 output groups** (**54 duplicate outputs eliminated**) where derivations built across different bootstrap stages (with distinct `.drv` hashes and toolchains) produced identical blinded content and automatically converged to the exact same content-addressed store path—including compiled C object files, static libraries, and binaries (`crt`, `libgetopt.a`, `libc.a`, `libtcc1.a`, `zlib-1.3.2-static`, `gcc-wrapper-simple-program-16.2.0`, and `casper-relocate-1.0.0`):

| Converged Content-Addressed `outputPath` | Stage Count | Distinct Input Hash Prefixes (`inputPath`) |
| :--- | :---: | :--- |
| `/nix/store/aqm99gyq87za2gs0h111gf90h5j08znh-crt` | **6** | `c100i3wl`, `8lbfxzhh`, `ax6p3zks`, `cr2fwxa8`, `in4lxyl2`, `8vshzzx0` *(compiled C runtime objects)* |
| `/nix/store/h2zm8gx40nhw8sj8757xh5pcpglw8gnb-gnu-config-2024-01-01` | **6** | `n41wrnzj`, `gqbwba4h`, `x6lr15n7`, `vjh3adfl`, `h4mv53xy`, `zf3wrhmm` |
| `/nix/store/1sid5bc540bia6li9ggk7sc7di5nm89h-update-autotools-gnu-config-scripts-hook` | **6** | `qhhb6xz5`, `iryy6bdg`, `5vy4gk8y`, `sk59smk7`, `lix213f8`, `mx9g3gy5` |
| `/nix/store/5l370ygzr8z5bqwznnm6nzj8wslwaci7-libgetopt.a` | **5** | `rsxndyy0`, `arzgm997`, `k79y1lnr`, `0kwsy1cm`, `wgfv3l0v` *(compiled C static library)* |
| `/nix/store/dm6q61ww6sj6nryvvpfnp3vnqd15jdl9-bash-5.3p20-doc` | **5** | `7vwnwicw`, `is5rwjyl`, `bvn9w9iv`, `819c065z`, `plf6jzl8` |
| `/nix/store/ckz06r96n7si38hsw57kwg3hhcpcpb31-bash-5.3p20-info` | **5** | `vzp36ld0`, `dsa4vab6`, `484km3jz`, `jvjppgsw`, `b4sk68p1` |
| `/nix/store/qm1m7lwjglsvq40mgx8sfnn6qf39xi9l-bash-5.3p20-man` | **5** | `zdsk5ryd`, `vrcsw3ij`, `ks0d6ma6`, `iqd3rbnv`, `6bc8vbgx` |
| `/nix/store/z2k3gfnq9jdx1s28a1rx6vg8znd17qzn-libc.a` | **3** | `p80l2blh`, `da2divww`, `i0j9n2qm` *(compiled C static library)* |
| `/nix/store/xs86i9sqqcgg6mcsnzpbq99jss90xn2m-libtcc1.a` | **2** | `naj0sji0`, `d12mrwn6` *(compiled TinyCC runtime library)* |
| `/nix/store/v6n18fglz508l2wipjzd2p1ggkm3kvqc-libtcc1.a` | **2** | `rh4xf4rv`, `42d2jjf1` |
| `/nix/store/2fy7jqh740kcrhyw64h72m4qhafvly99-crt` | **2** | `hh534gvz`, `2adssbqg` |
| `/nix/store/g3w1wr54b7z25bi8444vpbdg57m32yzq-libc.a` | **2** | `ypk0x6wj`, `0i45h2yq` |
| `/nix/store/2ij5fxacpw3fvgcpxim9ym1gzjp4kwp1-libgetopt.a` | **2** | `zamp026s`, `y4bgya5h` |
| `/nix/store/7vjc10pgi6dgc2q9c77h8w3dk9n49xgm-libtcc1.a` | **2** | `4fm23ri1`, `l4n1piyw` |
| `/nix/store/s29di2xr2v2160c4zd1nwcaki7i2d3y6-xz-get-version-5.8.3` | **2** | `6fyhgpkx`, `1c8jfjg7` |
| `/nix/store/x7wig6vw6xm4a3clps7f8c9awzsabhab-gcc-wrapper-simple-program-16.2.0` | **2** | `rxqlb5sp`, `grsw2j11` *(compiled C binary)* |
| `/nix/store/gzd38an8gszgj6akdslinbfzqa9g0hyq-zlib-1.3.2-static` | **2** | `1m657k6i`, `m6zmblhc` *(compiled C static library)* |
| `/nix/store/p8mqjin5gf9acxzdgk722ylh6d50vxis-gmp-6.3.0-info` | **2** | `8xv16yrs`, `73mxh8zg` |
| `/nix/store/r2dg2j6svx26z7z9kkp6b5laskkxmr21-mpfr-4.2.2-doc` | **2** | `3bjg2ip7`, `r7cwy8ic` |
| `/nix/store/wc4dm2kbkipfx437qa39aq0kc39q1lxd-mpfr-4.2.2-info` | **2** | `3hlvw6ip`, `21111m24` |
| `/nix/store/7yzszhjc0rc672w7fc2f7yy144laawsq-gettext-1.0-info` | **2** | `hlqjm2h5`, `qx98d7fz` |
| `/nix/store/48h0sips9jb6v0hj1ifm8p6x9iy9b8p2-binutils-2.46-info` | **2** | `1pp92wmf`, `yxq7631r` |
| `/nix/store/6m4dwraccjx17z33jy2vd2rzx34p8dsv-binutils-2.46-man` | **2** | `09557wj1`, `5p1a23zr` |
| `/nix/store/8ws7417rr2580vpnki6giz3f9i2rlk7q-binutils-wrapper-2.46-info` | **2** | `f9fpklnz`, `dymds4bc` |
| `/nix/store/9x36mllk0gi7mf5xg1ld9198f8c0bxil-binutils-wrapper-2.46-man` | **2** | `31g88k4i`, `v74w87h1` |
| `/nix/store/fmw3dqw6q6ib0ycyv9nji5ddbrznl0bi-xz-5.8.4-doc` | **2** | `5pqcixb4`, `yfvz9jfj` |
| `/nix/store/vylvm9x06p1d72bk6iqi4pv6kp2m9izz-xz-5.8.4-man` | **2** | `jyn67q39`, `qkq4pc2d` |
| `/nix/store/nrb7wgxzbdc1p38lg1km2dp68fy8q1q4-version-check-hook` | **2** | `2q6q3k8x`, `133b732l` |
| `/nix/store/q9pdkyi530rxzi17l6winsp680z842mn-casper-relocate-1.0.0` | **2** | `6pvpanb6`, `dliqgcrg` *(statically-linked C relocator binary)* |

### 4.3 Key Technical Findings from the Real Bootstrap
1. **Zero Injected Files & Pure `NAR` $\to$ `NAR` In-Process Stream Relocation**:
   - In `minimal-bootstrap` (`stage0-posix` through `tinycc` and `gcc-4.6.4`), early derivations (`hex1`, `hex2`, `M0`, `M2`, `blood-elf-0`) execute in a bare sandbox with **no `/bin/sh`, `find`, or `sed`**, and many outputs are single regular executable files (`S_ISREG`) rather than directories (`S_ISDIR`).
   - Because [`relocateNAR`](../nix/src/libstore/build/derivation-builder-impl.cc#L108-L240) operates directly on the NAR stream in C++ and only spawns `$out/nix-support/relocate.sh` when a package explicitly provides one, all early bootstrap outputs relocated in-process without injecting any extra files into `$out`.
2. **Selective Binary Cache Substitution (`type(*drv).isCA()`)**:
   - Standard binary caches (`cache.nixos.org`) index input-addressed derivations by `<inputHash>-<name>`, whereas `CAFixed` derivations (source tarballs and `stage0-posix` seeds) are indexed by fixed content hash.
   - Restricting binary cache substitution to `type(*drv).isCA()` in [`DerivationGoal::haveDerivation`](../nix/src/libstore/build/derivation-goal.cc#L93) and [`Store::queryMissing`](../nix/src/libstore/misc.cc#L268) allows CASPER to fetch fixed-output source tarballs from `cache.nixos.org` while building and relocating all input-addressed derivations locally.
3. **Resolving `allowedReferences` & `disallowedRequisites` After Relocation**:
   - Foundational packages in `nixpkgs` (`glibc-2.44`, `gcc-16.2.0`, `bootstrap-stage*-stdenv-linux`) specify strict `allowedReferences`, `allowedRequisites`, `disallowedReferences`, and `disallowedRequisites` lists containing evaluation-time `<inputHash>-<name>` store paths.
   - Updating [`checkOutputs`](../nix/src/libstore/build/derivation-check.cc#L23-L52) to resolve those paths through `store.resolveInputPath` (and the current derivation's `outputs` map) allowed every bootstrap stage's reference checks to pass without modifying `nixpkgs`.
4. **Empirical `.gz` Recompression Across Self-Referencing & Multi-Output Packages**:
   - Outputs containing `.gz` files (`493` outputs in the `nixpkgs-unstable` GNOME closure) automatically receive `$out/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate` and rewrite compressed self-references deterministically in-stream, passing both Pass 3 fixed-point verification and offline `nix-hash --casper` verification:
     1. `020qzyqpxw8ngbpjyq8di8nmszhscix7-xkeyboard-config-2.49`: `share/man/man7/xkeyboard-config-2.7.gz` (rewrote `/nix/store/9shnara8yfzvp4xsxcpaiwqihpmnaybl-xkeyboard-config-2.49` $\to$ `/nix/store/020qzyqpxw8ngbpjyq8di8nmszhscix7-xkeyboard-config-2.49`).
     2. `1g493f8bri5dwrd1vc0kcadgnq7n6qjz-rhash-1.4.6`: `share/man/man1/rhash.1.gz` (rewrote `/nix/store/dp1km76rk17fxasqsb8dl3sbf6lrvdzz-rhash-1.4.6` $\to$ `/nix/store/1g493f8bri5dwrd1vc0kcadgnq7n6qjz-rhash-1.4.6`).
     3. `4wx239vi7wy48mxnxrrd7ik3w7ac6a6r-xorg-server-21.1.25`: `share/man/man5/xorg.conf.5.gz` and `share/man/man1/Xserver.1.gz` (rewrote `/nix/store/ghxkzxdinvd3z0fvr23wy8q1s924ss14-xorg-server-21.1.25` $\to$ `/nix/store/4wx239vi7wy48mxnxrrd7ik3w7ac6a6r-xorg-server-21.1.25`).
     4. `nrq6fsc45bppd18g1h8xqhk9wxgykhrf-file-5.48-man` (`__structuredAttrs = true` multi-output sibling rewrite): `share/man/man1/file.1.gz`, `share/man/man3/libmagic.3.gz`, and `share/man/man4/magic.4.gz` (rewrote `/nix/store/m1kzyvj1xgsa6max4jbv1amzv02gc694-file-5.48/share/misc/magic*` $\to$ `/nix/store/443jhcyij6pjmimgckn72dgb83arzvr8-file-5.48/share/misc/magic*`).

---

## 5. Full NixOS Unstable GNOME 51.0 Wayland Desktop (`pkgs.nixosTests.gnome`)

Building `pkgs.nixosTests.gnome` from `nixpkgs-unstable` ([`2074cc672349f14240fb7ea90d509e0b643e9dd4`](https://github.com/NixOS/nixpkgs/commit/2074cc672349f14240fb7ea90d509e0b643e9dd4), `2026-11-12T14:50:34Z`) on top of the source-bootstrapped `casper-store` compiled and verified **3,395 relocated derivations** (**5,712 relocated outputs**, deduplicated into **5,551 unique content-addressed store paths**—eliminating **161 duplicate outputs**) and booted the resulting NixOS system inside QEMU (`qemu-11.1.2` + `virtiofsd-1.14.0`) into a full GNOME 51.0 Wayland desktop session (`gdm-51.0` $\to$ `mutter-51.0` $\to$ `gnome-shell-51.0` $\to$ `org.gnome.Console`), passing all `nixosTests.gnome` subtests (in addition to the earlier NixOS 25.11 GNOME 49.4 verification at **2,717 derivations** / **5,213 relocated outputs** $\to$ **5,077 unique content-addressed store paths**):

| Component | Evaluation Input Path (`<inputHash>-<name>`) | Relocated Content-Addressed Path (`<outHash>-<name>`) |
| :--- | :--- | :--- |
| **`python3-3.14.10`** | `/nix/store/wxnydg8k9v4m3myavyasbxb2j3l48wn5-python3-3.14.10` | `/nix/store/388rb79dnwfqb7hjhp2x60mvlpws58wc-python3-3.14.10` |
| **`llvm-22.1.8`** | `/nix/store/canpyf1pis85qf3av6abdjvwlzz1z60j-llvm-22.1.8` | `/nix/store/b2m1ah971p78zz7jh13sjp11x3nr5lhi-llvm-22.1.8` |
| **`rustc-1.99.1`** | `/nix/store/4i9hh2l7pkp5yqxhdg3gqskpixx1crv7-rustc-1.99.1` | `/nix/store/0mj2ljdk1347wd1d5x7lxcwhb6x6zqj7-rustc-1.99.1` |
| **`linux-6.18.63`** | `/nix/store/22g8yyavxa3ssqngrdmbf4cmh8470qb4-linux-6.18.63` | `/nix/store/npfc5l33n6jp2w87dpcnf0scry0g9q5y-linux-6.18.63` |
| **`initrd-linux-6.18.63`** | `/nix/store/clg58hhqgcbvj6nl4kapc4gqy070ggyf-initrd-linux-6.18.63` | `/nix/store/byn9jb5ghalyhwpnv72v89b18pjghldn-initrd-linux-6.18.63` |
| **`mesa-26.3.0`** | `/nix/store/j1hdban4wp6yrk94sals912dqcf8apg7-mesa-26.3.0` | `/nix/store/brq6ld3ssjdgs27njlkgbw2ngzwd0zww-mesa-26.3.0` |
| **`gtk4-4.24.0`** | `/nix/store/p3py5l3gq5bq08c7qk02nsqv58m2m85h-gtk4-4.24.0` | `/nix/store/l6x6x4i85fxms0dhmzaahvw1qvwqrxb1-gtk4-4.24.0` |
| **`webkitgtk-2.54.2+abi=6.0`** | `/nix/store/y4xh1jyp9dmpq9387m29zlynyx033r6a-webkitgtk-2.54.2+abi=6.0` | `/nix/store/v7cmdwnhqisah6x15265dpv6mb89hp6h-webkitgtk-2.54.2+abi=6.0` |
| **`mutter-51.0`** | `/nix/store/fx0jzfyld259jy1p39gyd4f0sn46s3bs-mutter-51.0` | `/nix/store/0ip1zbd2dw2qvsisn1kn1rc1srhcsmbf-mutter-51.0` |
| **`gdm-51.0`** | `/nix/store/ljlrakw053h5w1lr5f85m99ik48wskzc-gdm-51.0` | `/nix/store/fkddkds0ilr4b25srs6x0hy7rcr6ply7-gdm-51.0` |
| **`gnome-shell-51.0`** | `/nix/store/khx740b4m5inqddghn8mjxvdc0va6hak-gnome-shell-51.0` | `/nix/store/hrh8hahp2miqk0qvrh5b412f16l04xg3-gnome-shell-51.0` |
| **`virtiofsd-1.14.0`** | `/nix/store/d7gwy967fasrrxl55pzgdbli4rdx8whw-virtiofsd-1.14.0` | `/nix/store/dap979abb1kbc1dymhhphwls9848mzaf-virtiofsd-1.14.0` |
| **`qemu-for-vm-tests-11.1.2`** | `/nix/store/32zz2qizagiiw6mvihgsdskfkrj41w67-qemu-for-vm-tests-11.1.2` | `/nix/store/kvmwa8wv51jkijn172bqv22g202yvci7-qemu-for-vm-tests-11.1.2` |
| **`nixos-system-machine-test`** | `/nix/store/d36s3mq9ffx6x88fvjr2a8569ls9f38j-nixos-system-machine-test` | `/nix/store/6s3rbmqckvam9pqfp4cghia5bya54866-nixos-system-machine-test` |
| **`nixos-test-driver-gnome`** | `/nix/store/9l5rippz8ycwap0sjwqli21lqz76jzl4-nixos-test-driver-gnome` | `/nix/store/cvi2iy95wcm2jw5vn8lmpw0afnydzyql-nixos-test-driver-gnome` |
