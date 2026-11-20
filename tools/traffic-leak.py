"""What a passive observer learns about the clinical state from the traffic.

For each reading the observer sees the first byte and the length of every
packet the reading produced. The best rule for each observed pattern is the
majority class; we report its recall of critical readings and the mutual
information between the observed pattern and the clinical state.

usage: python3 tools/traffic-leak.py results-paper
"""
import sys
import numpy as np
import pandas as pd


def leak(g, v):
    if v == "v2":   # two-mode design: mode byte and length are visible
        view = g.groupby("reading").apply(lambda x: str(tuple(sorted(zip(x.first_byte, x.length)))), include_groups=False)
    else:           # CAOT-ECC: the first byte is the device id, so only lengths matter
        view = g.groupby("reading").apply(lambda x: str(tuple(sorted(x.length))), include_groups=False)
    y = g.groupby("reading").critical.first().astype(bool)
    d = pd.DataFrame({"o": view, "y": y})
    pred = d.o.map(d.groupby("o").y.mean()) >= 0.5
    j = pd.crosstab(d.o, d.y, normalize=True)
    px, py = j.sum(axis=1), j.sum(axis=0)
    mi = sum(j.loc[a, c] * np.log2(j.loc[a, c] / (px[a] * py[c]))
             for a in j.index for c in j.columns if j.loc[a, c] > 0)
    h = -sum(q * np.log2(q) for q in py if q > 0)
    return dict(readings=len(d), critical=int(d.y.sum()), distinct_views=d.o.nunique(),
                critical_recall=round((pred & d.y).sum() / max(d.y.sum(), 1), 4),
                mi_bits=round(mi, 6), state_entropy_bits=round(h, 4))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "results-paper"
    rows = []
    s = pd.read_csv(f"{out}/traffic-streams.csv")
    for (st, v), g in s.groupby(["stream", "version"]):
        rows.append(dict(stream=st, version=v, **leak(g, v)))
    e = pd.read_csv(f"{out}/traffic-eicu.csv")
    for v, g in e.groupby("version"):
        rows.append(dict(stream="eicu", version=v, **leak(g, v)))
    r = pd.DataFrame(rows)
    r.to_csv(f"{out}/traffic-leak.csv", index=False)
    print(r.to_string(index=False))
