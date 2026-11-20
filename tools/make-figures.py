"""Figures of the paper.

usage: python3 tools/make-figures.py results-paper figures
"""
import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import numpy as np
import pandas as pd

R = Path(sys.argv[1] if len(sys.argv) > 1 else "results-paper")
F = Path(sys.argv[2] if len(sys.argv) > 2 else "figures"); F.mkdir(exist_ok=True)
BLUE, ORANGE, INK, MUTED, GRAY = "#2a78d6", "#eb6834", "#222222", "#777777", "#c9c9c9"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": MUTED,
                     "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
                     "axes.spines.top": False, "axes.spines.right": False, "savefig.dpi": 300})


def fig_formats():
    """Byte layout of the frames seen on the wire, 64-byte reading."""
    rows = [
        ("Two-mode design, routine", [("mode", 1, ORANGE), ("hdr", 20, GRAY), ("ciphertext", 64, BLUE), ("tag", 16, GRAY)]),
        ("Two-mode design, window", [("mode", 1, ORANGE), ("hdr", 24, GRAY), ("signature", 64, ORANGE)]),
        ("Two-mode design, critical", [("mode", 1, ORANGE), ("header with E, N", 72, GRAY), ("signature", 64, ORANGE), ("ciphertext", 64, BLUE), ("tag", 16, GRAY)]),
        ("CAOT-ECC, every reading", [("hdr", 20, GRAY), ("encrypted record", 131, BLUE), ("tag", 16, GRAY)]),
    ]
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    for i, (label, parts) in enumerate(rows):
        y = len(rows) - 1 - i; x = 0
        for name, n, c in parts:
            wv = max(n, 4)                       # a 1-byte field is drawn 4 units wide
            ax.add_patch(Rectangle((x, y + 0.15), wv, 0.7, fc=c, ec="white", lw=1.5))
            if n >= 20:
                ax.text(x + wv / 2, y + 0.5, name, ha="center", va="center", fontsize=7,
                        color="white" if c != GRAY else INK)
            x += wv
        total = sum(n for _, n, _ in parts)
        ax.text(-4, y + 0.5, label, ha="right", va="center", fontsize=8, color=INK)
        ax.text(x + 3, y + 0.5, f"{total} B", ha="left", va="center", fontsize=8, color=INK)
    ax.set_xlim(-120, 250); ax.set_ylim(-0.35, len(rows)); ax.axis("off")
    ax.text(0, -0.2, "Orange: fields that tell an observer the clinical state (the thin bar is the 1-byte mode).",
            fontsize=7.5, color=MUTED, va="top")
    ax.text(0, -0.45, "CAOT-ECC record = kind, length, reading padded to the bucket, 64-byte signature slot.",
            fontsize=7.5, color=MUTED, va="top")
    fig.savefig(F / "Figure 1.png", bbox_inches="tight"); plt.close(fig)


def fig_observer():
    t = pd.read_csv(R / "traffic-streams.csv")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.7))
    for ax, st, title in [(axes[0], "ecg", "ECG stream (MIT-BIH 100)"), (axes[1], "vitals", "Vital-sign stream (MIMIC)")]:
        g = t[t.stream == st]
        for k, (v, mk) in enumerate([("v2", "o"), ("v3", "s")]):
            gv = g[g.version == v]
            for crit, c in [(0, BLUE), (1, ORANGE)]:
                d = gv[gv.critical == crit]
                cnt = d.length.value_counts()
                ax.scatter(cnt.index, np.full(len(cnt), k + (0.12 if crit else -0.12)), s=12 + 60 * np.sqrt(cnt / cnt.max()),
                           color=c, marker=mk, alpha=0.9, label=("critical" if crit else "routine") if (k == 0) else None)
        ax.set_yticks([0, 1], ["two-mode\ndesign", "CAOT-ECC"])
        ax.set_xscale("log"); ax.set_xlabel("Packet length seen by the observer (bytes)")
        ax.set_title(title, fontsize=9, color=INK); ax.set_ylim(-0.6, 1.6)
        ax.grid(axis="x", color="#e5e5e5", lw=0.6); ax.set_axisbelow(True)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.07), fontsize=8)
    fig.tight_layout(); fig.savefig(F / "Figure 2.png", bbox_inches="tight"); plt.close(fig)


def fig_device():
    m = pd.read_csv(R / "mcu-v3.csv").drop_duplicates("function").set_index("function")
    cal = 1.45
    ms = lambda f: m.loc[f, "ms_at_120MHz"] * cal
    w = 16
    items = [("ECIES-P256", ms("pkt_ecies"), GRAY), ("Sethi et al. 2025 (no auth.)", ms("pkt_sethi"), GRAY),
             ("Two-mode design, critical", ms("pkt_caot_critical"), GRAY),
             ("CAOT-ECC, critical", ms("pkt_caot3_critical"), BLUE),
             ("Two-mode design, routine (w=16)", ms("pkt_caot_routine") + (ms("pkt_caot_window")) / w, GRAY),
             ("CAOT-ECC, routine (w=16)", ms("pkt_caot3_routine") * (w - 1) / w + ms("pkt_caot3_window") / w, BLUE),
             ("Anwar et al. 2025, data packet", ms("pkt_anwar"), GRAY)]
    fig, ax = plt.subplots(figsize=(6.2, 2.9))
    y = np.arange(len(items))[::-1]
    ax.barh(y, [v for _, v, _ in items], color=[c for *_, c in items], height=0.6)
    for yy, (n, v, _) in zip(y, items):
        ax.text(v * 1.08, yy, f"{v:.2f} ms" if v < 10 else f"{v:.1f} ms", va="center", fontsize=8, color=INK)
    ax.set_yticks(y, [n for n, _, _ in items]); ax.set_xscale("log"); ax.set_xlim(0.05, 400)
    ax.set_xlabel("Device time per 64-byte reading, emulated Cortex-M4 at 120 MHz, calibrated (log scale)")
    ax.grid(axis="x", color="#e5e5e5", lw=0.6); ax.set_axisbelow(True)
    fig.savefig(F / "Figure 3.png", bbox_inches="tight"); plt.close(fig)


def fig_window():
    m = pd.read_csv(R / "mcu-v3.csv").drop_duplicates("function").set_index("function")
    cal = 1.45
    r3, s3 = m.loc["pkt_caot3_routine", "ms_at_120MHz"] * cal, m.loc["pkt_caot3_window", "ms_at_120MHz"] * cal
    ws = np.array([1, 2, 4, 8, 16, 32, 64, 128])
    cost = (r3 * (ws - 1) + s3) / ws
    fig, ax = plt.subplots(figsize=(6.2, 2.6))
    ax.plot(ws, cost, color=BLUE, marker="o", ms=4, lw=2, label="device time per routine reading")
    ax.set_xscale("log", base=2); ax.set_xticks(ws, [f"{w}\n({w} s)" for w in ws])
    ax.set_xlabel("Window size w (in brackets: longest wait for a signature at one reading per second)")
    ax.set_ylabel("ms per routine reading")
    ax.grid(color="#e5e5e5", lw=0.6); ax.set_axisbelow(True)
    fig.savefig(F / "Figure 4.png", bbox_inches="tight"); plt.close(fig)
    return pd.DataFrame({"w": ws, "ms_per_reading": cost.round(3)})


if __name__ == "__main__":
    fig_formats(); fig_observer(); fig_device(); fig_window()
    print("figures written to", F)
