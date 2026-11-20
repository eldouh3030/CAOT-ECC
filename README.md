# CAOT-ECC

Reference implementation, experiments and formal models for **CAOT-ECC**, a context-aware
protocol for Internet of Medical Things (IoMT) streams that protects critical and routine
readings differently **without revealing to a network observer which readings are critical**.

The repository reproduces every table and figure of the paper *CAOT-ECC: Context-Aware
Protection of IoMT Streams Without Revealing the Clinical Context*.

## Protocol in short

Every reading, routine or critical, is sent as **exactly one frame of fixed size** on a
forward-secure HKDF key chain:

```
frame = header (device, session, counter, time; 20 B)
        || AES-256-GCM( kind | length | reading padded to the bucket | 64-byte signature slot )
        || tag (16 B)
```

| Reading | Signature slot |
|---|---|
| routine | zeros |
| critical | Ed25519 over header and padded record (proof of origin for this reading) |
| routine that closes a window of *w* frames | Ed25519 over header, padded record and the running hash of the window |

The kind, the padding and every signature are inside the authenticated encryption, so the
length, number and order of frames do not depend on the clinical state. A signed session
initialisation (ephemeral X25519, HKDF) runs on a timer, never on a clinical event. An optional
fixed-slot send policy with cover frames also hides timing.

## Naming in the code

| In the code / CSV files | In the paper |
|---|---|
| `caot3`, `CAOT-v3-C16`, `CAOT-v3-R16`, `v3` | **CAOT-ECC** |
| `caot2`, `CAOT-v2-C`, `CAOT-v2-R16`, `v2` | the **two-mode design** used as a reference (critical mode with an ephemeral key per packet, routine mode with a key chain and separate window packets) |

## Repository layout

| Path | Content |
|---|---|
| `src/crypto.*` | Thin C++17 wrappers over OpenSSL 3.x (X25519, Ed25519, P-256, RSA, HKDF, AES-GCM, ChaCha20-Poly1305) |
| `src/caot3.*` | **CAOT-ECC**: device and gateway, fixed-size frames, piggybacked window signatures, cover frames |
| `src/caot2.*` | Two-mode design (reference) |
| `src/schemes.*` | All compared schemes behind one interface (same primitives, same harness) |
| `src/tests.cpp` | 43 functional and adversarial tests of the shared code base |
| `src/traffic.cpp` | 11 CAOT-ECC tests and the eICU traffic-analysis run |
| `src/realdata.cpp` | MIT-BIH ECG and MIMIC vital-sign streams with a clinical policy, including observer traces |
| `src/bench.cpp` | Primitive, per-scheme and window-size benchmarks |
| `mcu-emulation/` | Cortex-M4 firmware (wolfCrypt) and the Unicorn-based cycle-counting harness |
| `formal/` | Tamarin models and full proof outputs |
| `tools/` | Data preparation, traffic-leak analysis and figure scripts (Python 3) |
| `data/` | Real data (MIT-BIH, MIMIC numerics, eICU demo sample) and synthetic sample files, see `data/README.md` |
| `results-paper/` | All results reported in the paper |

## Build

Requirements: a C++17 compiler, CMake ≥ 3.16 and OpenSSL ≥ 3.0.

**Linux / macOS**
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

**Windows (Visual Studio 2022)**
1. Install OpenSSL for Windows (64-bit), e.g. to `C:\Program Files\OpenSSL-Win64`.
2. *File → Open → Folder* and select this folder; choose the `x64-Release` configuration;
   *Build → Build All*.
3. Copy `libcrypto-3-x64.dll` from `C:\Program Files\OpenSSL-Win64\bin` next to the executables
   in `out\build\x64-Release` (or add that folder to `PATH`).

## Reproducing the results

Run from the repository root:
```
mkdir results
build/caot-tests                                                    # 43 tests
build/caot-traffic --stream data/eicu-stream.csv --out results --bucket 32   # 11 tests + eICU traffic
build/caot-realdata --data data --out results                       # ECG and vital-sign streams
build/caot-bench --out results --reps 1000                          # desktop costs
python3 tools/traffic-leak.py results                               # observer recall and mutual information
python3 tools/make-figures.py results figures                       # Figures 1-4
```

| Output file | Paper |
|---|---|
| `traffic-streams.csv`, `traffic-eicu.csv`, `traffic-leak.csv` | Table 1, Figure 2 |
| `schemes.csv` | Table 4 |
| `primitives.csv` | Section 8.1 |
| `stream-ecg.csv`, `stream-vitals.csv` | Table 6 |
| `window.csv` | window-size benchmark of the two-mode design |
| `mcu-v3.csv` (from `mcu-emulation/`) | Table 5, Figures 3 and 4 |
| `slots.csv` | Table 7 |

The files in `results-paper/` were produced on one core of an Intel Xeon at 2.30 GHz, Ubuntu
24.04, GCC 13.3 and OpenSSL 3.0.13 (see `results-paper/environment.txt`).

## Emulated Cortex-M4 measurements

See `mcu-emulation/README.md`. The firmware is built with clang for `thumbv7em-none-eabihf`
against wolfCrypt 5.7.6 and run in the Unicorn engine; the harness counts instructions and
cycles with the Cortex-M4 timing model. The CAOT-ECC sender functions are `pkt_caot3_routine`,
`pkt_caot3_critical` and `pkt_caot3_window` (plan `firmware/plan-v3.txt`). The paper multiplies
the cycles by 1.45, the ratio measured between the model and published wolfCrypt timings on a
120 MHz Cortex-M4 board.

## Formal verification

```
cd formal
./prove.sh                     # CAOT-ECC: 12 lemmas, proved one by one -> caot3-hidden-proof.txt
tamarin-prover --prove combined.spthy   # two-mode design: 11 lemmas
```
Verified with Tamarin 1.10.0 and Maude 3.5. The CAOT-ECC lemmas cover reading secrecy,
reading authentication, non-repudiation of critical readings and of windows, the one-wayness
of the key chain, and that neither the critical nor the window signature ever becomes known
to the attacker. Proving the lemmas one at a time keeps memory use low.

## Data

See `data/README.md` for sources and licences. Please cite the original databases when using them.

## Citation

If you use this code, please cite the accompanying paper (details will be added on publication)
and this repository (`CITATION.cff`).

## License

Code: MIT (see `LICENSE`). Data files keep their original licences (see `data/README.md`).
