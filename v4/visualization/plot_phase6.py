"""Create publication-oriented Phase-6 plots from generated CSV results."""
from __future__ import annotations
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "processed" / "phase6_mean_sd.csv"
PLOT_DIR = ROOT / "plots"


def bar(summary, metric, ylabel, filename, higher_is_better=True):
    s = summary.set_index("configuration")
    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = range(len(s.index))
    ax.bar(x, s[f"{metric}_mean"], yerr=s[f"{metric}_std"], capsize=4)
    ax.set_xticks(list(x), list(s.index), rotation=15, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(f"Phase-6 {ylabel}: mean ± SD across 10 seeds")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(PLOT_DIR / filename, dpi=200)
    plt.close(fig)


def main():
    if not SUMMARY.exists():
        raise SystemExit("Run phase6_experiment.py first.")
    summary = pd.read_csv(SUMMARY)
    PLOT_DIR.mkdir(exist_ok=True)
    bar(summary, "f1", "F1", "phase6_f1_mean_sd.png")
    bar(summary, "fpr", "FPR", "phase6_fpr_mean_sd.png", False)
    bar(summary, "fnr", "FNR", "phase6_fnr_mean_sd.png", False)
    bar(summary, "benign_pdr", "Benign PDR", "phase6_benign_pdr_mean_sd.png")
    bar(summary, "cpu_percent", "CPU (%)", "phase6_cpu_mean_sd.png", False)
    bar(summary, "rtt_ms", "RTT (ms)", "phase6_rtt_mean_sd.png", False)
    bar(summary, "packet_in_to_flow_mod_ms_mean", "Packet-In → Flow-Mod (ms)", "phase6_control_latency_mean_sd.png", False)
    print("Phase-6 plots generated in plots/")


if __name__ == "__main__":
    main()
