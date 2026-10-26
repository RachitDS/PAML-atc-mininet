"""Generate Phase-6B research plots from saved mean/SD results."""
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "processed" / "phase6b_mean_sd.csv"
PLOTS = ROOT / "plots"


def bar_metric(df, metric, title, ylabel, filename, lower_is_better=False):
    fig, ax = plt.subplots(figsize=(9, 5))
    x = range(len(df))
    ax.bar(list(x), df[f"{metric}_mean"], yerr=df[f"{metric}_std"], capsize=4)
    ax.set_xticks(list(x), df["configuration"], rotation=15, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(PLOTS / filename, dpi=220)
    plt.close(fig)


def main():
    df = pd.read_csv(SUMMARY)
    PLOTS.mkdir(exist_ok=True)
    bar_metric(df, "f1", "Phase-6B Detection F1", "F1 score", "phase6b_f1.png")
    bar_metric(df, "benign_pdr", "Phase-6B Benign Packet Delivery", "Benign PDR", "phase6b_benign_pdr.png")
    bar_metric(df, "attack_block_rate", "Phase-6B Attack Blocking", "Attack block rate", "phase6b_attack_block_rate.png")
    bar_metric(df, "rtt_ms", "Phase-6B Service RTT", "RTT (ms)", "phase6b_rtt.png")
    print(f"Generated plots in {PLOTS}")


if __name__ == "__main__":
    main()
