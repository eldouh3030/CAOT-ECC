#!/usr/bin/env python3
"""Convert the PhysioNet records used in the paper into simple CSV files.

Inputs (data/):
  mitbih/100.dat, 100.hea, 100.atr      MIT-BIH Arrhythmia Database, record 100
  mimic-numerics/*n.hea, *n.dat          MIMIC-II/III waveform matched subset,
                                         minute-by-minute ICU numerics
Outputs:
  mitbih/100-annotations.csv             sample, time_s, code, symbol, abnormal
  vitals-real.csv                        record, minute, HR, SpO2, SYS, DIA, RESP

Only the Python standard library is used.
"""
import csv, os, struct, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

# MIT annotation codes (WFDB ecgcodes.h)
SYMBOLS = {1: "N", 2: "L", 3: "R", 4: "a", 5: "V", 6: "F", 7: "J", 8: "A", 9: "S", 10: "E",
           11: "j", 12: "/", 13: "Q", 14: "~", 16: "|", 18: "s", 19: "T", 20: "*", 21: "D",
           22: '"', 23: "=", 24: "p", 25: "B", 26: "^", 27: "t", 28: "+", 29: "u", 30: "?",
           31: "!", 32: "[", 33: "]", 34: "e", 35: "n", 36: "@", 37: "x", 38: "f", 39: "(",
           40: ")", 41: "r"}
BEATS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 25, 34, 35, 37, 38, 41}


def read_atr(path):
    data = open(path, "rb").read()
    i, t, out = 0, 0, []
    while i + 1 < len(data):
        w = data[i] | (data[i + 1] << 8)
        i += 2
        a, v = w >> 10, w & 0x3FF
        if a == 0 and v == 0:
            break
        if a == 59:                                   # SKIP: 32-bit interval follows
            hi = data[i] | (data[i + 1] << 8)
            lo = data[i + 2] | (data[i + 3] << 8)
            i += 4
            iv = (hi << 16) | lo
            if iv >= 1 << 31:
                iv -= 1 << 32
            t += iv
            continue
        if a in (60, 61, 62):                         # NUM, SUB, CHN
            continue
        if a == 63:                                   # AUX string
            i += v + (v & 1)
            continue
        t += v
        out.append((t, a))
    return out


def mitbih():
    hea = open(os.path.join(ROOT, "mitbih", "100.hea")).read().split()
    fs = float(hea[2])
    anns = read_atr(os.path.join(ROOT, "mitbih", "100.atr"))
    path = os.path.join(ROOT, "mitbih", "100-annotations.csv")
    n_beats = n_abn = 0
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sample", "time_s", "code", "symbol", "is_beat", "abnormal"])
        for s, a in anns:
            beat = a in BEATS
            abn = beat and a != 1
            n_beats += beat
            n_abn += abn
            w.writerow([s, f"{s / fs:.3f}", a, SYMBOLS.get(a, "?"), int(beat), int(abn)])
    print(f"MIT-BIH 100: {len(anns)} annotations, {n_beats} beats, {n_abn} abnormal -> {path}")


def read_numerics(hea_path):
    lines = [l for l in open(hea_path).read().splitlines() if l and not l.startswith("#")]
    rec = lines[0].split()
    nsig, nsamp = int(rec[1]), int(rec[3])
    sigs = []
    for l in lines[1:1 + nsig]:
        p = l.split()
        gain = float(p[2].split("/")[0].split("(")[0])
        sigs.append((p[0], gain, p[-1]))
    dat = os.path.join(os.path.dirname(hea_path), sigs[0][0])
    raw = open(dat, "rb").read()
    n = min(nsamp, len(raw) // (2 * nsig))
    rows = []
    for k in range(n):
        vals = struct.unpack_from("<" + "h" * nsig, raw, 2 * nsig * k)
        row = {}
        for (fname, gain, name), v in zip(sigs, vals):
            row[name] = None if v == -32768 else v / gain
        rows.append(row)
    return rec[0], rows


def mimic():
    d = os.path.join(ROOT, "mimic-numerics")
    out = os.path.join(ROOT, "vitals-real.csv")
    kept = 0
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["record", "minute", "HR", "SpO2", "SYS", "DIA", "RESP"])
        for name in sorted(os.listdir(d)):
            if not name.endswith("n.hea"):
                continue
            rec, rows = read_numerics(os.path.join(d, name))
            for m, r in enumerate(rows):
                hr, spo2, resp = r.get("HR"), r.get("SpO2"), r.get("RESP")
                sys_ = r.get("ABPSys") or r.get("NBPSys")
                dia = r.get("ABPDias") or r.get("NBPDias")
                # keep minutes with plausible, present HR and SpO2 (0 = sensor off)
                if not hr or not spo2 or hr <= 0 or spo2 <= 0:
                    continue
                w.writerow([rec, m, round(hr), round(spo2),
                            round(sys_) if sys_ else "", round(dia) if dia else "",
                            round(resp) if resp else ""])
                kept += 1
    print(f"MIMIC numerics: {kept} minute records with HR and SpO2 -> {out}")


if __name__ == "__main__":
    mitbih()
    mimic()
