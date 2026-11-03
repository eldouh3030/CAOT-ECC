# CAOT-ECC

Reference implementation, experiments and formal models for **CAOT-ECC**, a context-aware
hybrid cryptographic protocol for Internet of Medical Things (IoMT) communication, and for the
analysis of low-entropy leakage in published IoMT designs.

The repository contains everything needed to reproduce the results reported in the paper:
the low-entropy leakage attacks on real ICU data (`src/leakage.cpp`), the protocol and the
baselines it is compared with, the experiments on real PhysioNet data, the emulated Cortex-M4
measurements (`mcu-emulation/`), and the Tamarin models, including the combined model of both
modes with packet loss (`formal/combined.spthy`).

Identifiers such as `caot2`, `CAOT-v2-C` and `CAOT-v2-R16` in the code and in the CSV files are
internal names of the current protocol version.

## Protocol in short

| Mode | Used for | Per packet |
|---|---|---|
| **Critical** | alarms, abnormal readings | fresh ephemeral X25519 key, HKDF-SHA256 key derivation bound to the header, AES-256-GCM, Ed25519 signature |
| **Routine** | normal periodic readings | one-time key from a forward-secure HKDF chain, AES-256-GCM, monotonic counter; one Ed25519 signature per window of *w* packets over a running hash |

A clinical context policy chooses the mode for each message. Replay protection uses a timestamp
window with a nonce cache (critical) or a strictly increasing counter (routine).

## Repository layout

| Path | Content |
|---|---|
| `src/crypto.*` | Thin C++17 wrappers over OpenSSL 3.x (X25519, Ed25519, P-256, RSA, HKDF, AES-GCM, ChaCha20-Poly1305) |
| `src/caot2.*` | CAOT-ECC: device and gateway, critical and routine modes, replay cache |
| `src/schemes.*` | All compared schemes behind one interface (same primitives, same harness) |
| `src/tests.cpp` | 43 functional and adversarial tests (replay, tampering, impersonation, packet loss, policy) |
| `src/realdata.cpp` | MIT-BIH ECG stream and MIMIC vital-sign stream with a clinical policy |
| `src/bench.cpp` | Primitive, per-scheme and window-size benchmarks |
| `src/leakage.cpp` | Low-entropy leakage attacks (L1-L4) on published IoMT patterns with real ICU data |
| `mcu-emulation/` | Cortex-M4 firmware (wolfCrypt) and the Unicorn-based cycle-counting harness |
| `formal/` | Tamarin models of both modes and the full proof output |
| `tools/prepare-data.py` | Converts the PhysioNet records to CSV (Python 3, standard library only) |
| `data/` | Real data (MIT-BIH, MIMIC numerics) and synthetic sample files, see `data/README.md` |
| `results-laptop/` | Laptop results reported in the paper (AMD Ryzen 5 4500U, Windows 11, MSVC, OpenSSL 3.5.6) |
| `mcu-emulation/results/` | Emulated Cortex-M4 cycle counts reported in the paper |

## Compared schemes

| Name in results | Scheme |
|---|---|
| `RSA-HYB` | RSA-2048 OAEP + RSA-PSS + AES-256-GCM |
| `ECIES-P256` | ECIES on P-256 + ECDSA-P256 + AES-256-GCM |
| `SETHI-2025` | Sethi et al., IEEE Access 13, 2025 (cryptographic part: ephemeral ECDH + ChaCha20) |
| `ANWAR-2025` | Anwar, Hendi and Anderson, ACM CPSIoTSec 2025 (Ed25519-authenticated X25519 session + ChaCha20-Poly1305) |
| `CAOT-v2-C`, `CAOT-v2-R16` | This work, critical and routine (w = 16) modes |

## Build

Requirements: a C++17 compiler, CMake ≥ 3.16 and OpenSSL ≥ 3.0.

**Windows (Visual Studio 2022)**
1. Install OpenSSL for Windows (64-bit), e.g. to `C:\Program Files\OpenSSL-Win64`.
2. *File → Open → Folder* and select this folder; choose the `x64-Release` configuration
   (configuration type `Release`); *Build → Build All*.
3. Copy `libcrypto-3-x64.dll` from `C:\Program Files\OpenSSL-Win64\bin` next to the executables
   in `out\build\x64-Release` (or add that folder to `PATH`).

**Linux / macOS**
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Reproducing the results

Run from the repository root (on Windows use `.\out\build\x64-Release\<program>.exe`):
```
mkdir results
build/caot-tests
build/caot-realdata --data data --out results
build/caot-leakage  --data data --out results --sample 200
build/caot-bench    --out results --reps 1000 --file data/mitbih/100.dat \
    --file data/sample-files/medical_record_text.txt --file data/sample-files/medical_report_pdf.pdf \
    --file data/sample-files/synthetic_ecg_medical_image.png --file data/sample-files/iomt_sensor_data.csv
```

| Output file | Content |
|---|---|
| `leakage.csv` | Plaintext recovery and equality leakage for patterns L1-L4 on real ICU data |
| `primitives.csv` | Cost of each cryptographic primitive |
| `schemes.csv` | Sender/receiver time (mean, SD, median, p95), wire size and overhead per scheme and payload |
| `window.csv` | Routine mode cost as a function of the window size *w* |
| `stream-ecg.csv` | MIT-BIH record 100 as a 1 packet/s stream; abnormal-beat seconds are critical |
| `stream-vitals.csv` | MIMIC vital-sign stream with an early-warning policy |

## Emulated Cortex-M4 measurements

See `mcu-emulation/README.md`. The firmware is built with clang for `thumbv7em-none-eabihf`
against wolfCrypt 5.7.6 and run in the Unicorn engine; the harness counts instructions and
cycles with the Cortex-M4 timing model. The paper multiplies the cycles by 1.45, the ratio
measured between the model and published wolfCrypt timings on a 120 MHz Cortex-M4 board.

## Formal verification

```
tamarin-prover --prove formal/critical-mode.spthy    # 3 lemmas
tamarin-prover --prove formal/routine-mode.spthy     # 8 lemmas
tamarin-prover --prove formal/combined.spthy         # both modes together, packet loss: 11 lemmas
```
Verified with Tamarin 1.10.0 and Maude 3.5; outputs are in `formal/*-proof.txt`.
Properties: payload secrecy (also under device-key compromise), injective agreement with replay
protection and KCI resistance (critical mode); payload secrecy, data-origin authentication,
one-wayness of the key chain and window non-repudiation (routine mode).

## Data

See `data/README.md` for sources and licences. Please cite the original databases when using them.

## Citation

If you use this code, please cite the accompanying paper (details will be added on publication)
and this repository (`CITATION.cff`).

## License

Code: MIT (see `LICENSE`). Data files keep their original licences (see `data/README.md`).
