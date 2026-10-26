"""Plots for Phase 6B.1 operational MTD/deception metrics."""
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
summary_path = ROOT / "results" / "processed" / "phase6b1_mean_sd.csv"
out_dir = ROOT / "plots"
out_dir.mkdir(exist_ok=True)


def bar(df, columns, labels, ylabel, filename):
    x = range(len(df))
    width = 0.8 / len(columns)
    plt.figure(figsize=(9, 5))
    for i, col in enumerate(columns):
        values = df[col].to_numpy()
        positions = [v + (i - (len(columns)-1)/2) * width for v in x]
        plt.bar(positions, values, width=width, label=labels[i])
    plt.xticks(list(x), df["configuration"], rotation=20, ha="right")
    plt.ylabel(ylabel)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / filename, dpi=160)
    plt.close()


def main():
    df = pd.read_csv(summary_path)
    a4 = df[df.configuration == "A4_FULL"].copy()

    bar(
        df,
        ["mtd_rotation_rate_mean"],
        ["MTD rotation rate"],
        "Rotations / confirmed attack events",
        "phase6b1_mtd_rotation_rate.png",
    )
    bar(
        df,
        ["deception_capture_rate_mean"],
        ["Deception capture rate"],
        "Captured / confirmed attack decisions",
        "phase6b1_deception_capture_rate.png",
    )
    bar(
        df,
        ["attack_block_rate_mean", "attack_diversion_rate_mean"],
        ["Attack block rate", "Attack diversion rate"],
        "Rate",
        "phase6b1_attack_block_vs_diversion.png",
    )
    bar(
        df,
        ["mtd_target_coverage_mean"],
        ["MTD target coverage"],
        "Fraction of configured targets observed",
        "phase6b1_target_coverage.png",
    )
    print("Generated Phase-6B.1 plots in:", out_dir)
    print("A4 rows:")
    print(a4[["configuration", "mtd_rotations_mean", "mtd_rotation_rate_mean", "decoy_hits_mean", "deception_capture_rate_mean", "attack_diversion_rate_mean"]].round(4).to_string(index=False))


if __name__ == "__main__":
    main()
