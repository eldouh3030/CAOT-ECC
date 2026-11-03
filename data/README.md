# Data

## Real data

| Folder / file | Source | Use |
|---|---|---|
| `mitbih/100.dat`, `100.hea`, `100.atr` | MIT-BIH Arrhythmia Database, record 100, PhysioNet | ECG stream (1080 B per second); beat annotations drive the critical/routine policy |
| `mitbih/100-annotations.csv` | derived from `100.atr` by `tools/prepare-data.py` | 2273 beats: 2239 N, 33 A, 1 V |
| `mimic-numerics/*` | MIMIC-II/III Waveform Database Matched Subset, minute-by-minute numerics of records s00001 and s25047, as redistributed in the WFDB sample data (MIT-LCP/wfdb-python, `sample-data/multi-segment`) | real ICU HR, SpO2, blood pressure, respiration |
| `vitals-real.csv` | derived from `mimic-numerics/` by `tools/prepare-data.py` | 1611 minute records with HR and SpO2 |

Regenerate the CSV files with `python3 tools/prepare-data.py`.

Please cite when using these data:
- G. B. Moody and R. G. Mark, "The impact of the MIT-BIH Arrhythmia Database," IEEE Eng. Med. Biol. Mag., vol. 20, no. 3, pp. 45–50, 2001.
- A. L. Goldberger et al., "PhysioBank, PhysioToolkit, and PhysioNet," Circulation, vol. 101, no. 23, pp. e215–e220, 2000.
- B. Moody, G. Moody, M. Villarroel, G. D. Clifford, I. Silva, "MIMIC-III Waveform Database Matched Subset," PhysioNet.

These records are distributed by PhysioNet under their original open licences; see the
corresponding PhysioNet project pages for the exact terms.

## Synthetic sample files

`sample-files/` contains generated (synthetic) files — a text record, a CSV of simulated sensor
readings, a PDF report, a synthetic ECG image and a mixed binary payload. They contain no patient
data and are used only to test different payload types and sizes.
