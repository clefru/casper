# Empirical Analysis of Self-Referencing Packages (Local `/nix/store`)

Querying the local Nix store database (`/nix/var/nix/db/db.sqlite`, 208,009 valid paths) shows why handling self-references (including `.gz` manpages, `.pyc` bytecode, `pkg-config`, and ELF `DT_RUNPATH`) is critical:

## 1. Overall Store Breakdown

| Category | Total Paths | Self-Referencing | Non-Self-Referencing | % Self-Ref | Total Size (GB) | Self-Ref Size (GB) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Input-addressed package outputs** (`ca IS NULL`) | **27,255** | **14,972** | **12,283** | **54.9%** | **258.60 GB** | **186.62 GB** |
| Fixed-output / Sources (`ca = fixed:*`) | 3,980 | 0 | 3,980 | 0.0% | 66.33 GB | 0.00 GB |
| Text / Eval files (`ca = text:*`) | 35 | 0 | 35 | 0.0% | 0.00 GB | 0.00 GB |
| Derivations (`*.drv`) | 176,739 | 0 | 176,739 | 0.0% | 0.64 GB | 0.00 GB |

## 2. Breakdown of Input-Addressed Outputs by Output / Package Type

| Output / Package Category | Total | Self-Referencing | Non-Self-Referencing | % Self-Ref | Why Self-References Occur |
| :--- | ---: | ---: | ---: | ---: | :--- |
| **Perl packages (`perl5*`)** | 616 | 616 | 0 | **100.0%** | `.packlist` and shebangs embed `$out` |
| **Dev outputs (`*-dev`)** | 637 | 593 | 44 | **93.1%** | `pkg-config` (`prefix=$out`) and CMake configs |
| **Python packages (`python3*`)** | 1,502 | 1,401 | 101 | **93.3%** | `.pyc` bytecode headers embed `$out/.../foo.py` |
| **Library outputs (`*-lib`)** | 1,093 | 855 | 238 | **78.2%** | ELF `DT_RUNPATH` includes `$out/lib` |
| **Primary outputs (`out`)** | 23,602 | 13,378 | 10,224 | **56.7%** | Mix of ELF RPATHs, wrapper scripts, `.gz` manpages, data |
| **Binary outputs (`*-bin`)** | 491 | 140 | 351 | **28.5%** | Most link against `*-lib` rather than `*-bin` |
| **TeX Live packages (`texlive-*`)** | 142 | 30 | 112 | **21.1%** | Mostly pure TeX macros/fonts |
| **Docs / Man / Info (`*-doc`, `*-man`, `*-info`)** | 1,388 | 6 | 1,382 | **0.4%** | Occasional `.gz` manpage / HTML doc embedding `$out` |
| **Data outputs (`*-data`)** | 44 | 0 | 44 | **0.0%** | Pure data files |

With `relocate.sh` normalizing self-references before hashing and rewriting them to the output hash afterward, **100% of packages** (both the 45.1% non-self-referencing and the 54.9% self-referencing packages, including those with `.gz` files) become truly content-addressed and deduplicatable.
