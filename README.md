# CASPER: Content-Addressable Store via Partial-blinding and Embedded Relocation

**CASPER** brings output-addressed (content-addressed) builds to Nix without `/nix/store` symlink stubs and without hardcoding file-format knowledge into Nix C++.

---

## 1. Core Innovations of CASPER

### 1.1 Breaking the Self-Reference Hash Loop via Partial Blinding
- Whenever a payload must embed a cryptographic hash or signature of itself, standard cryptographic protocols break the circularity by computing the digest over a **blinded** representation of the payload in which the hash/signature slot is either stripped or overwritten with a fixed placeholder (such as all zeros or `xxxx...`):
  - In **cryptocurrency transactions** (e.g., Bitcoin's `SIGHASH` and Ethereum transaction signing), the `scriptSig` or signature fields are zeroed/blanked before hashing the transaction payload to be signed, and the resulting signature is then placed into those fields.
  - In **signed API requests, JWTs, and XML-DSig / SAML enveloped signatures**, as well as **PE Authenticode binaries**, **RPM/FIT images**, and **IPv4/TCP/ICMP packets**, the embedded signature or checksum field is zeroed out before the hash is computed over the payload.
- We call this **partial blinding**: only the self-reference slots (`/nix/store/<input-hash>-<name>`) inside the derivation output are overwritten with a blinding placeholder (`/nix/store/<blind-hash>-<name>`), while all external dependency references (`/nix/store/<dep-hash>-<dep>`) remain unblinded.
- In CASPER, an output's content address `<output-hash>` is defined not as the raw SHA-256 hash of the final output, but as the SHA-256 hash of the **partially blinded** output. Because the placeholder is independent of both `<input-hash>` and `<output-hash>`, the hash loop disappears, and two derivations with different input hashes that produce identical blinded content converge to the exact same `<output-hash>`.

### 1.2 Delegating Partial Blinding & Relocation to the Derivation (`$out/nix-support/relocate.sh`)
- Why can't Nix simply perform partial blinding in C++ using a naive byte-string search-and-replace? Because in real software packages, self-references are not always stored in uncompressed plaintext. Consider a `.gz`-compressed manpage or archive inside `$out` that embeds `/nix/store/<input-hash>-<name>`: a naive byte-string blinder scanning raw file bytes will never see the reference inside the compressed Deflate bitstream and therefore cannot blind or relocate it.
- While we could special-case `.gz` files in Nix itself, this is undesirable as so many versions of hidden references could exist. It is up to the software packager to fix those up.
- CASPER's second invention is to **delegate the task of blinding and relocating self-references to the derivation output itself**, by embedding a relocator (`$out/nix-support/relocate.sh`) inside the output.
- Crucially, embedding the blinder/relocator inside the output **does not re-introduce the hash loop**: the task of blinding and relocating can be defined **abstractly** (`relocate.sh <old-self> <new-self>`, taking the source and target store-path strings as parameters) without making any concrete reference to `<input-hash>` or `<output-hash>` inside the script itself. Because the relocator's own bytes remain completely invariant across blinding and relocation, it can live inside `$out` and be hashed alongside the rest of the partially blinded output without causing a hash cycle.

### 1.3 Sandboxed `NAR` $\to$ `NAR` Stream Relocation (`stdin` $\to$ `stdout`)
- Instead of mutating a directory tree in place on the host filesystem, `relocate.sh <old-self> <new-self>` runs inside an isolated sandbox (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWNET`, seccomp/Landlock) as a pure **`NAR` (`stdin`) $\to$ `NAR` (`stdout`) stream transformer** with zero host filesystem access:
  - **Pass 1 (Blinding & Hashing)**: Nix serializes `$out` as a NAR stream, pipes it through `relocate.sh "<input-hash>-<name>" "<blind-hash>-<name>"`, and feeds `stdout` directly into Nix's C++ SHA-256 `HashSink` with **zero disk writes** to derive `<output-hash>`.
  - **Pass 2 (Relocation & Trusted Unpacking)**: Nix pipes the blinded NAR through `relocate.sh "<blind-hash>-<name>" "<output-hash>-<name>"` and unpacks `stdout` via its trusted C++ `RestoreSink` to `/nix/store/<output-hash>-<name>` while simultaneously computing the final `narHash` and scanning store references.
  - **Pass 3 (Fixed-Point Verification)**: Immediately after unpacking, Nix re-blinds `/nix/store/<output-hash>-<name>` back to `<blind-hash>-<name>` and verifies that the SHA-256 hash matches Pass 1—proving at build time that `<output-hash>` is a true fixed point.

### 1.4 Unsolvable Hash Loop for the Relocator via Dynamic Blinding Constant
- Whenever `$out/nix-support/relocate.sh` is present, it is required to be a **symlink pointing to a standalone relocator derivation** (`/nix/store/<relocator-hash>-<relocator-name>/...`).
- Nix extracts `<relocator-hash>` directly from the `relocate.sh` symlink target and uses `<relocator-hash>-<name>` as the blinding constant (`blindSelf`).
- This forces an **unsolvable cryptographic hash loop** into the relocator itself: for a relocator to anticipate or hardcode its blinding constant (for example, to branch differently between Pass 1 and Pass 2), it would have to embed its own SHA-256 store hash inside its own binary or script before being hashed.

### 1.5 Downstream Dependency Rewriting (Zero Store Symlinks)
- When a dependency `foo` is relocated from `/nix/store/<input-hash>-foo` to `/nix/store/<output-hash>-foo`, Nix records the mapping in SQLite (`PathRewrites` and `DerivationOutputs`).
- Before building any downstream derivation `bar`, Nix rewrites `<input-hash>-foo` $\to$ `<output-hash>-foo` across `bar`'s builder arguments, environment variables, structured attributes, and sandbox inputs so `bar` builds directly against `/nix/store/<output-hash>-foo`.

### 1.6 Replacing Dependencies on the Fly (CPU Optimization & Rapid Security Patching)
- Because `relocate.sh` is a general `<old-hash>-<name>` $\to$ `<new-hash>-<name>` `NAR` $\to$ `NAR` stream transformer, it can rewrite **dependency hashes** in addition to self-references (similar in spirit to Nixpkgs' `replaceDependencies`, but format-aware and content-addressed).
- This enables both **rapid security updates deep in the stack** (swapping a CVE-patched `openssl`, `glibc`, or `zlib` across a built system in seconds without recompiling reverse dependencies) and **targeted CPU optimization** (swapping in a `-march=native` `glibc` or `openblas`), producing new content-addressed store paths that pass `nix-hash --casper` (see [docs/DEP_REPLACE.md](docs/DEP_REPLACE.md)).

---

## 2. Quickstart & How to Use CASPER

### 2.1 Building CASPER Nix

Compile the modified Nix implementation in the [`nix/`](nix) submodule:

```bash
meson compile -C nix/build
```

The resulting binaries (`nix`, `nix-build`, `nix-store`, `nix-hash`, etc.) are placed in `nix/build/src/nix/`.

---

### 2.2 Building Nixpkgs Packages with `casper-overlay.nix`

[`casper-overlay.nix`](casper-overlay.nix) provides a lightweight Nixpkgs overlay that builds [`casper-relocate`](casper-relocate.c) (a statically-linked C `NAR` $\to$ `NAR` stream relocator handling uncompressed files, symlinks, directory entries, and `.gz` files) and symlinks `$out/nix-support/relocate.sh -> ${casper-relocate}/bin/casper-relocate` whenever an output contains `.gz` files. Outputs without `.gz` files use Nix's built-in format-agnostic C++ `relocateNAR` with zero extra files.

#### Build a Single Package or Closure

```bash
./nix/build/src/nix/nix-build \
  --store "$PWD/casper-store" \
  -E 'import <nixpkgs> { overlays = [ (import ./casper-overlay.nix) ]; }' \
  -A hello
```

> [!TIP]
> **Incremental vs. Full Bootstrap**: You do not need to rebuild `stdenv` from scratch to use CASPER. Pre-existing store paths without a `PathRewrites` entry act as fixed leaves (`resolveInputPath` returns them unchanged), while newly built derivations are blinded, content-addressed, and relocated by CASPER.

#### Run the Full From-Scratch Bootstrap (`stage0-posix` + `stdenv`)

```bash
./bootstrap.sh
```

Running [`bootstrap.sh`](bootstrap.sh) builds both `minimal-bootstrap.kaem` (49 derivations from `hex0`) and the full Nixpkgs `stdenv` (`stage0` $\to$ `stage4` $\to$ `stdenv` $\to$ `hello`, 264 derivations) into `./casper-store`, relocating **313 derivation outputs** and automatically deduplicating **20 cross-stage output groups** into **274 unique content-addressed store paths** (see [docs/BOOTSTRAPPING_AND_PACKAGING.md](docs/BOOTSTRAPPING_AND_PACKAGING.md#4-real-world-bootstrap-verification-casper-store)).

---

### 2.3 Verifying Store Paths Offline (`nix-hash --casper` / `nix hash casper`)

Because `<relocator-hash>` is preserved on the `$out/nix-support/relocate.sh` symlink inside the final store object, you can independently recompute and verify the content address of any `/nix/store/<output-hash>-<name>` path without needing the `.drv` or SQLite database:

```bash
# Legacy CLI:
./nix/build/src/nix/nix-hash --casper \
  --store "$PWD/casper-store" \
  /nix/store/sn0pwh1agh2hnlbgm61ra3qr6yiz6ja8-hello-2.12.2

# Modern CLI:
./nix/build/src/nix/nix --extra-experimental-features nix-command \
  hash casper --store "$PWD/casper-store" \
  /nix/store/sn0pwh1agh2hnlbgm61ra3qr6yiz6ja8-hello-2.12.2
```

`nix-hash --casper` locates `$out/nix-support/relocate.sh`, extracts `<relocator-hash>` from the symlink target, blinds `<output-hash>-<name>` $\to$ `<relocator-hash>-<name>`, hashes the resulting NAR stream with SHA-256, and verifies that the recomputed `casper:out` store path matches `/nix/store/<output-hash>-<name>`.

---

### 2.4 Custom Relocators for Opaque Formats (`withCasper`)

When a package embeds self-references inside an opaque format beyond `.gz` (such as `.zst`/`.xz` archives or Python `RECORD` manifests), wrap the package with `withCasper` from [`casper-overlay.nix`](casper-overlay.nix). `withCasper` builds a standalone relocator derivation (`casper-relocate-<name>`) and symlinks it at `$out/nix-support/relocate.sh`:

```nix
final: prev:
let
  casperOverlay = import ./casper-overlay.nix final prev;
  inherit (casperOverlay) withCasper;
in casperOverlay // {
  # Example 1: Directory-based custom hook (unpacks NAR in sandbox tmpfs, runs hook, dumps NAR)
  someZstPackage = withCasper {
    relocateExtra = ''
      find "$target" -type f -name "*.zst" | while IFS= read -r zf; do
        zstd -dc "$zf" | sed "s|$old|$new|g" | zstd -q > "$zf.casper-tmp"
        mv "$zf.casper-tmp" "$zf"
      done
    '';
  } prev.someZstPackage;

  # Example 2: Pure NAR -> NAR stream filter hook (stdin -> stdout)
  someStreamPackage = withCasper {
    relocateStream = ''
      exec ${final.casper-relocate}/bin/casper-relocate "$old" "$new"
    '';
  } prev.someStreamPackage;
}
```

---

## 3. Background: Why Self-References Block Content-Addressed Nix

### 3.1 The Self-Reference Hash Loop
In traditional Nix, derivation outputs are **input-addressed**: a derivation with masked input hash `abcdef...` builds its output directly into `/nix/store/abcdef...-foo-1.2.3`, and that path is registered in the store regardless of the actual bytes produced. Two derivations with different inputs that compile to the exact same output cannot share a store path or short-circuit downstream rebuilds.

Moving to **output-addressed (content-addressed) derivations**, where every built object in `/nix/store` is named by the cryptographic hash of its output contents (`/nix/store/<output-hash>-<name>`), runs directly into **self-referencing outputs**:
- Over **54.9%** of packages (and **72.2%** by store size; see [docs/EMPIRICAL_ANALYSIS.md](docs/EMPIRICAL_ANALYSIS.md)) embed their own `$out` store path inside their build outputs—in ELF `DT_RUNPATH`s, shebangs, wrapper scripts, `pkg-config` `.pc` files, Python `.pyc` bytecode, and compressed files such as `.gz` manpages.
- During the build, `$out` must already be known so compilers and build scripts can embed `/nix/store/<hash>-<name>` into binaries and data files.
- Yet if `<hash>` is the cryptographic hash of the output, then the output's contents must contain `<hash>` before `<hash>` can be computed—an **unsolvable cryptographic hash loop**:
  $$H = \text{Hash}\big(\text{output containing } \texttt{/nix/store/} \parallel H \parallel \texttt{-foo}\big)$$

### 3.2 Why Store Symlink Stubs Are Not Enough
One way to sidestep the self-reference loop without rewriting package contents is to build in `/nix/store/<input-hash>-<name>`, move the result to `/nix/store/<output-hash>-<name>`, and leave a **symlink** at `/nix/store/<input-hash>-<name> -> /nix/store/<output-hash>-<name>`. This is undesirable for two reasons:
1. **Double Filesystem Lookups on Every Access**: Every `execve`, shared library load (`openat` via `DT_RUNPATH`), header include, or file read through `/nix/store/<input-hash>-<name>` requires **two filesystem lookups** (first resolving the input-hash symlink, then traversing the target output-addressed directory). On cold storage, spinning disks, overlayfs, or network/remote stores, doubling every filesystem lookup slows down execution and builds considerably.
2. **Leaky Input-Hash Pollution**: Binaries still embed `<input-hash>` rather than `<output-hash>`, so two builds producing identical functional content still differ at the byte level in their embedded paths, and `/nix/store` accumulates permanent symlink stubs for every historical input hash.

---

## 4. Documentation

- **[Detailed Architecture (`docs/DETAILS.md`)](docs/DETAILS.md)**: End-to-end operational pipeline, Mermaid flowchart, `NAR` $\to$ `NAR` stream protocol, and multi-output/downstream dependency rewriting.
- **[On-the-Fly Dependency Replacement (`docs/DEP_REPLACE.md`)](docs/DEP_REPLACE.md)**: Using `relocate.sh` to swap ABI-compatible dependencies (such as a CPU-optimized `glibc`) across built packages without recompiling.
- **[Binary Caching & Build Non-Determinism (`docs/NON_DETERMINISM.md`)](docs/NON_DETERMINISM.md)**: `input -> output` realisation index for binary caches, build non-determinism trade-offs, and symlink strategies (`input_hash -> output_hash` vs. `competing_output_hash -> master_output_hash`) to prevent diamond dependency duplication.
- **[Nixpkgs Bootstrapping & Packaging Guide (`docs/BOOTSTRAPPING_AND_PACKAGING.md`)](docs/BOOTSTRAPPING_AND_PACKAGING.md)**: Packaging trade-offs for opaque formats, the dual-location rebuild trick, [`casper-overlay.nix`](casper-overlay.nix) internals, and full `stage0-posix` / `stdenv` bootstrap tables.
- **[Nix C++ Implementation Overview (`docs/NIX_IMPLEMENTATION.md`)](docs/NIX_IMPLEMENTATION.md)**: Summary of modified C++ files in the [`nix/`](nix) submodule.
- **[Security Considerations & Threat Model (`docs/SECURITY.md`)](docs/SECURITY.md)**: Sandbox threat model, prototype vulnerabilities, dynamic `<relocator-hash>` blinding construction, and Pass 3 fixed-point verification.
- **[Alternatives Considered (`docs/ALTERNATIVES_CONSIDERED.md`)](docs/ALTERNATIVES_CONSIDERED.md)**: Discarded design alternatives (in-place directory mutation, separate `hash.sh`, `/nix/build`, and `.`-prefixed store paths).
- **[Empirical Self-Reference Analysis (`docs/EMPIRICAL_ANALYSIS.md`)](docs/EMPIRICAL_ANALYSIS.md)**: Measurements of self-referencing store paths across Nixpkgs by output category and size.
