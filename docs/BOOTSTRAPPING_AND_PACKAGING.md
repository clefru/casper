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
    1. Checks each directory output (`${outputs:-out}`) for `.gz` files (`find "$_casper_dir" -type f -name '*.gz' -print -quit`) and creates a direct symlink `$_casper_dir/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate` **only when `.gz` files are present**—allowing outputs without `.gz` files to use the fast in-process C++ `relocateNAR` with zero extra files or references.
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

### 3.2 Mode B: Full End-to-End `stdenv` Bootstrap from `bootstrap-tools`
When bootstrapping `nixpkgs` from scratch (`stdenvStages` 0 through final `stdenv`):
1. **Stage 0 (`bootstrap-tools`)**:
   - Downloaded as a fixed-output derivation (`CAFixed`), unpacked by `busybox` (`unpack-bootstrap-tools.sh`), and relocated in-process by C++ [`relocateNAR`](../nix/src/libstore/build/derivation-builder-impl.cc#L108-L240) without requiring any external tools in the sandbox.
2. **Static Libraries (`.a` Archives) Across Bootstrap Stages (`stage0` $\to$ `stage1` $\to$ `stage2` $\to$ `stage3` $\to$ `stdenv`)**:
   - Early GCC/glibc bootstrap stages build static `.a` archives (`libgcc.a`, `libc.a`).
   - Standard `ar` archives store each member's byte size as a fixed-width decimal ASCII header and do not store member checksums. Because `<inputHash>` (32 chars), `<blindHash>` (32 chars), and `<outHash>` (32 chars) have the exact same byte length, `RewritingSink` relocation inside `.a` archives preserves member sizes and symbol tables without needing `ranlib`.
3. **Ecosystem-Level Hooks for Full Nixpkgs Coverage**:
   - Rather than overriding individual packages one by one, most non-plaintext formats in `nixpkgs` belong to language/framework ecosystems where a single hook covers thousands of packages:
     - **Python (`buildPythonPackage`)**: `*.dist-info/RECORD` files list SHA-256 hashes of installed entry-point scripts; when `relocate.sh` rewrites `$out` inside an entry-point script, `RECORD` either needs its hash updated or stripped.
     - **Haskell (`ghc` / `cabal`)**: `package.conf.d/package.cache` is a binary cache of `.conf` files containing `$out` paths; `relocate.sh` for GHC package DBs can re-run `ghc-pkg recache` or rewrite the binary cache.
     - **Linux Kernel Modules (`linux`)**: `.ko.xz` or `.ko.zst` modules that embed `$out` firmware/module paths need `xz`/`zstd` decompression/recompression in `relocate.sh`.
     - **Java / JVM (`.jar` / `.zip`)**: Unpacking/repacking `.jar` files only when `grep` detects a self-reference inside the uncompressed stream.
     - **macOS (`darwin`)**: Mach-O binaries with ad-hoc code signatures invalidate their signature when rewriting the `LC_RPATH` load command, requiring `codesign -f -s -` in `relocate.sh` on Darwin.

---

## 4. Real-World Bootstrap Verification (`casper-store`)

Both Nixpkgs bootstrap chains were executed end-to-end into `casper-store` using `./nix/build/src/nix/nix-build` and [`casper-overlay.nix`](../casper-overlay.nix), producing **313 relocated derivation outputs** (`PathRewrites` rows in `casper-store/nix/var/nix/db/db.sqlite`) that converged to **274 unique content-addressed outputs**:

1. **Source-Only `stage0-posix` Bootstrap (49 Derivations)**:
   - Built from `hex0-1.6.0` (`stage0-posix-1.6.0-source`) through `hex1`, `hex2`, `catm`, `M0`, `cc_arch`, `M2-0`, `M2`, `blood-elf-0`, `M1-0`, `hex2-1`, `M1`, `hex2`, `kaem-unwrapped`, `mescc-tools`, `mescc-tools-extra`, and `kaem-1.6.0` (`/nix/store/5ac8fyvhhjj13m4r54kc53b6bbhy7nfw-kaem-1.6.0`).
2. **Full Nixpkgs `stdenv` Bootstrap (`stage0` $\to$ `stage1` $\to$ `stage-xgcc` $\to$ `stage2` $\to$ `stage3` $\to$ `stage4` $\to$ `stdenv-linux` $\to$ `hello-2.12.2`)**:
   - **264 `stdenv` bootstrap outputs** built, blinded, content-hashed, and relocated across all bootstrap stages via the streaming `NAR` $\to$ `NAR` pipeline without a single Nixpkgs package modification.

### 4.1 Key Bootstrap Milestones (`inputPath` $\to$ Content-Addressed `outputPath`)

| Stage / Milestone | Evaluation Input Path (`<inputHash>-<name>`) | Relocated Content-Addressed Path (`<outHash>-<name>`) |
| :--- | :--- | :--- |
| **`stage0-posix` (`hex1-1.6.0`)** | `/nix/store/pvk596baqdg5hnmvnjsb1fbca6bz5j4v-hex1-1.6.0` | `/nix/store/3m87j2yh62phlzc3f5nhj4l0m75n55x1-hex1-1.6.0` |
| **`stage0-posix` (`M2-1.6.0`)** | `/nix/store/3vmryl2mpq9rib67bi6clfvb44nym9jr-M2-1.6.0` | `/nix/store/f2xdw0rhj6k5a3dsirczd0gnlf53f50x-M2-1.6.0` |
| **`stage0-posix` (`mescc-tools`)** | `/nix/store/k7847sdmcmfqvgpc7ycd5a4wpx49xan0-mescc-tools-1.6.0` | `/nix/store/97n0b1z6g61n330w9qn5r6b1mc4yawzl-mescc-tools-1.6.0` |
| **`stage0-posix` (`kaem-1.6.0`)** | `/nix/store/9a0qmi15cidrn9kca5j820dw0qan13c8-kaem-1.6.0` | `/nix/store/5ac8fyvhhjj13m4r54kc53b6bbhy7nfw-kaem-1.6.0` |
| **Stage 0 (`bootstrap-tools`)** | `/nix/store/razasrvdg7ckplfmvdxv4ia3wbayr94s-bootstrap-tools` | `/nix/store/30n2a6x7vsvxj1mzvrvhg8m89f41ci37-bootstrap-tools` |
| **Stage 0 (`stdenv-linux`)** | `/nix/store/ajrdf015k5ipn89gyh06isniabysrkcw-bootstrap-stage0-stdenv-linux` | `/nix/store/s5j2ficvrlkjb6dhw9ay9zgglh573w98-bootstrap-stage0-stdenv-linux` |
| **Stage 1 (`stdenv-linux`)** | `/nix/store/wkqjkkwnwhs270sav1mrdz089cmydmj8-bootstrap-stage1-stdenv-linux` | `/nix/store/dk3i95c49wjpsa5xc62cby077qk83y3a-bootstrap-stage1-stdenv-linux` |
| **Stage xgcc (`xgcc-14.3.0`)** | `/nix/store/nvv5arlnf72xkvpnmnw78ywgdnvx92q3-xgcc-14.3.0` | `/nix/store/g5inkmc4j8pdclpyi2z37vszcr252wib-xgcc-14.3.0` |
| **Stage xgcc (`stdenv-linux`)** | `/nix/store/azdg07c0qmzmj6cpnbpgmrh9gk1jl91d-bootstrap-stage-xgcc-stdenv-linux` | `/nix/store/75x0pfcacqpsf6h8ppd9fz983r08n69n-bootstrap-stage-xgcc-stdenv-linux` |
| **Stage 2 (`linux-headers-6.16.7`)** | `/nix/store/9a975kwlj5hyfq8y6hsapfaj5pj7g090-linux-headers-6.16.7` | `/nix/store/b7xga9z9x1rbkj6agr51pgg9v4yf4d5w-linux-headers-6.16.7` |
| **Stage 2 (`glibc-2.40-224`)** | `/nix/store/7nbi22pcc92y2fqbkyp7h3srvvklmckb-glibc-2.40-224` | `/nix/store/94f38yglcijsz5a8kv7hr3bz2w1is1r0-glibc-2.40-224` |
| **Stage 3 (`stdenv-linux`)** | `/nix/store/j7sbhs7c8wi0rxfh2f8wyngjdj5lb3z5-bootstrap-stage3-stdenv-linux` | `/nix/store/rpnwisgkssmkndx9yamgvhgmh376ipb7-bootstrap-stage3-stdenv-linux` |
| **Stage 4 (`gcc-14.3.0`)** | `/nix/store/ipr6y28viyqkhkg58rdvy27m01q5j5nh-gcc-14.3.0` | `/nix/store/ixh56dfh4lq5r87cfl8v3dv7q230hw0h-gcc-14.3.0` |
| **Stage 4 (`coreutils-9.8`)** | `/nix/store/hqkszxk2c0cxvd04xa4gsaqs182dw8l2-coreutils-9.8` | `/nix/store/nkydbxdsfg1jjyli6mzz5ahfj3m6mj0h-coreutils-9.8` |
| **Stage 4 (`bash-5.3p3`)** | `/nix/store/3hgg7pr65imdrifqqh3flg3arvkc2r22-bash-5.3p3` | `/nix/store/3894m0zrq35da26lpk0kk2lasdmc98vw-bash-5.3p3` |
| **Final `stdenv-linux`** | `/nix/store/0i25iw4373868kjqhafvmd6pn1wwzkh3-stdenv-linux` | `/nix/store/5cbirwzcqq4rdwib11lh1k5rbz3xma8l-stdenv-linux` |
| **Final `hello-2.12.2`** | `/nix/store/18bbdvag5v2f3d4y37pdbkzvh7s71cw4-hello-2.12.2` | `/nix/store/sn0pwh1agh2hnlbgm61ra3qr6yiz6ja8-hello-2.12.2` |

### 4.2 Cross-Stage Content-Addressed Deduplication (20 Output Groups Across Stages 0–4)
Querying `PathRewrites` in `casper-store/nix/var/nix/db/db.sqlite` showed **20 output groups** (39 duplicate outputs eliminated) where derivations built across different bootstrap stages (with distinct `.drv` hashes and toolchains) produced identical blinded content and automatically converged to the exact same content-addressed store path:

| Converged Content-Addressed `outputPath` | Stage Count | Distinct Input Hash Prefixes (`inputPath`) |
| :--- | :---: | :--- |
| `/nix/store/h2zm8gx40nhw8sj8757xh5pcpglw8gnb-gnu-config-2024-01-01` | **6** | `nkp2jjfx`, `wqzpxm4j`, `y6alivz8`, `xdj1hdnn`, `nynfiaxg`, `ay97s1f2` |
| `/nix/store/1sid5bc540bia6li9ggk7sc7di5nm89h-update-autotools-gnu-config-scripts-hook` | **6** | `ivs0xima`, `w3f3v1va`, `44bzap4q`, `zmbyl8wb`, `zxixwkhw`, `4s62rh5i` |
| `/nix/store/isksmxafyj4ldqkn6zwbrz4cq1rp7qxz-bash-5.3p3-info` | **5** | `pqqcpb5q`, `4pz2asx9`, `k52n6fp4`, `ycy1vg2n`, `f4q2risa` |
| `/nix/store/mflf4dq4x1wmsglpra9gsnq49z8an7mf-bash-5.3p3-man` | **5** | `vsrzjz05`, `83s5r9zn`, `irvzpqbc`, `3br10pn2`, `y3hrz22j` |
| `/nix/store/xdkj3ydj7q3px091xay4wx9hgwl8hidx-bash-5.3p3-doc` | **5** | `sidp11qn`, `5i8iqc88`, `sia47i7m`, `d5h5g51l`, `m569srhy` |
| `/nix/store/ii3700nq7nnfhp8zfssjczarw60izsdv-nuke-references` | **4** | `rxxjh38q`, `wwiqgin8`, `jrabk1pr`, `2kh0hlwq` |
| `/nix/store/0xz45i1lvf06pjxydpddid2nglir332r-expand-response-params` | **2** | `gk36k5fd`, `bzkq151p` *(compiled C binary deduplicated across stages)* |
| `/nix/store/kcrsbmlryh3rjgmx1ns9lrshsj3i6zxs-bash-5.3p3-debug` | **2** | `2hg82qsg`, `i7p4sb8d` |
| `/nix/store/78x0j5kl28kgf46699s3pisjafbax3j0-binutils-2.44-man` | **2** | `2b43ga3y`, `5951bdp9` |
| `/nix/store/k8yn35adnbq8vivkljg6bjb10lh5bwfx-binutils-2.44-info` | **2** | `b4b5lfds`, `ynws37nl` |
| `/nix/store/6i8rmmr9b3w6nfm1mbad4a8rj05ykjb8-binutils-wrapper-2.44-man` | **2** | `641ksb94`, `iwh74pj4` |
| `/nix/store/5ddi5vhhma11h30v7mqa5b9ipq63fqcj-binutils-wrapper-2.44-info` | **2** | `0s7vn1v9`, `fmf1v6h8` |
| `/nix/store/8w7bd80468acw2ki886x4mcz9jw52b13-python-setup-hook.sh` | **2** | `4441jg4a`, `1ay695zg` |
| `/nix/store/p8mqjin5gf9acxzdgk722ylh6d50vxis-gmp-6.3.0-info` | **2** | `3g3f04ja`, `a945qkvw` *(distinct from `2ypdc6zv6xxgg65aykz0177m9wgn4rga-gmp-with-cxx-6.3.0-info` via name-mixed `casper:out` derivation)* |
| `/nix/store/r2dg2j6svx26z7z9kkp6b5laskkxmr21-mpfr-4.2.2-doc` | **2** | `3m1319j9`, `fiqrdsdy` |
| `/nix/store/wc4dm2kbkipfx437qa39aq0kc39q1lxd-mpfr-4.2.2-info` | **2** | `s6w6ji55`, `5fmqqppa` |
| `/nix/store/3zpq1q2dnsklbf41wlvfkx8rwjf2s8d4-xz-5.8.3-doc` | **2** | `x4qgpmhz`, `h4ch4ldb` |
| `/nix/store/2kfnv0hyikydq1mmfpqh7ld64wq96fdl-xz-5.8.3-man` | **2** | `yzci0g7r`, `34qc1s1k` |
| `/nix/store/29a0hwkx4wfj3xbiz5233gqg9g1g6qwh-libxcrypt-4.5.2-man` | **2** | `cc7r666h`, `yhficm51` |
| `/nix/store/fzm5c1csn6slg3zsb850lznsy96mg52k-gettext-0.25.1-info` | **2** | `nky8g413`, `wripq293` |

### 4.3 Key Technical Findings from the Real Bootstrap
1. **Zero Injected Files & Pure `NAR` $\to$ `NAR` In-Process Stream Relocation**:
   - In `minimal-bootstrap` (`stage0-posix`), early derivations (`hex1`, `hex2`, `M0`, `M2`, `blood-elf-0`) execute in a bare sandbox with **no `/bin/sh`, `find`, or `sed`**, and many outputs are single regular executable files (`S_ISREG`) rather than directories (`S_ISDIR`).
   - Because [`relocateNAR`](../nix/src/libstore/build/derivation-builder-impl.cc#L108-L240) operates directly on the NAR stream in C++ and only spawns `$out/nix-support/relocate.sh` when a package explicitly provides one, all 313 bootstrap outputs relocated in-process without injecting any extra files into `$out`.
2. **Selective Binary Cache Substitution (`type(*drv).isCA()`)**:
   - Standard binary caches (`cache.nixos.org`) index input-addressed derivations by `<inputHash>-<name>`, whereas `CAFixed` derivations (source tarballs, `bootstrap-tools.tar.xz`, `stage0-posix` seeds) are indexed by fixed content hash.
   - Restricting binary cache substitution to `type(*drv).isCA()` in [`DerivationGoal::haveDerivation`](../nix/src/libstore/build/derivation-goal.cc#L93) and [`Store::queryMissing`](../nix/src/libstore/misc.cc#L268) allows CASPER to fetch fixed-output source tarballs from `cache.nixos.org` while building and relocating all input-addressed derivations locally.
3. **Resolving `allowedReferences` & `disallowedRequisites` After Relocation**:
   - Foundational packages in `nixpkgs` (`glibc-2.40-224`, `gcc-14.3.0`, `bootstrap-stage*-stdenv-linux`) specify strict `allowedReferences`, `allowedRequisites`, `disallowedReferences`, and `disallowedRequisites` lists containing evaluation-time `<inputHash>-<name>` store paths.
   - Updating [`checkOutputs`](../nix/src/libstore/build/derivation-check.cc#L23-L52) to resolve those paths through `store.resolveInputPath` (and the current derivation's `outputs` map) allowed every bootstrap stage's reference checks to pass without modifying `nixpkgs`.
4. **Empirical `.gz` Recompression in Multi-Output Packages**:
   - Multi-output packages (`outputs = [ "out" "man" ... ]`) whose `.gz` manpages embed sibling `$out` references (`file-5.45-man`, `gettext-0.25.1-man`) are topologically ordered after `$out`, symlinked to [`casper-relocate`](../casper-relocate.c) when `.gz` files are present, and rewritten in-stream:
     1. `rzkzgcpi35061aphd7nvw9q4567ws09d-file-5.45-man`: `share/man/man1/file.1.gz`, `share/man/man3/libmagic.3.gz`, and `share/man/man4/magic.4.gz` (rewrote `/nix/store/018l43lbsqbrsasrfdcxxb5s4s161fkr-file-5.45/share/misc/magic*` $\to$ `/nix/store/40xf2hs1hr0934ad6a5w1kb6krc16g7a-file-5.45/share/misc/magic*`).
     2. `vbrchwv2wc4s32cdnf6ns12b751b5v3f-gettext-0.25.1-man` (Stage 3): `share/man/man1/gettext.1.gz` and `share/man/man1/ngettext.1.gz` (rewrote `/nix/store/qawh4dvis37x3nvvsd1n53v13gy9yq9g-gettext-0.25.1/share/locale` $\to$ `/nix/store/mj7f7qmykivmz7cmwq62gn0zd5w173is-gettext-0.25.1/share/locale`).
     3. `8gjj4hnbj7fr4bfyd2yp5bfvbx5lh7d7-gettext-0.25.1-man` (Stage 4): `share/man/man1/gettext.1.gz` and `share/man/man1/ngettext.1.gz` (rewrote `/nix/store/yfnzmmv8r4wzgg2f0fci4xl874lm7w5x-gettext-0.25.1/share/locale` $\to$ `/nix/store/6jz09pa69k6nfijv6ij5laf6k4m8qh2z-gettext-0.25.1/share/locale`).
