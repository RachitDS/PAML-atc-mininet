# Phase 6B.1 — MTD + Deception Measurement Refinement

## Status
**REUSED:** Phase-6B A1–A4 experiment, 10-seed protocol, PAML detector, adaptive ATC, MTD and deception components.

**MODIFIED:** The A4 evaluation now exposes explicit operational MTD/deception metrics rather than expecting the attack-block-rate metric alone to demonstrate their contribution.

**NEW:**
- MTD rotation count
- MTD attack-event count
- MTD rotation rate
- unique active target count
- target coverage
- decoy-hit count
- deception attack decisions
- deception capture / redirect rate
- diverted attack traffic (pps)
- attack diversion rate
- A3-vs-A4 operational effect report

## Why this phase exists
Phase 6B already showed a coherent progression:

`A1 static threshold -> A2 PAML -> A3 PAML+ATC -> A4 FULL`

But A3 and A4 had almost identical attack-block rates. That made it difficult to demonstrate what MTD and deception were doing. Phase 6B.1 therefore measures those mechanisms directly while keeping the underlying policy behavior unchanged.

This is a measurement refinement, not a claim that synthetic simulation proves real-world MTD/deception effectiveness.

## Run
From the project root with the virtual environment activated:

```powershell
python -m pytest
python phase6b1_experiment.py
```

## Main outputs
- `results/raw/phase6b1_seed_results.csv`
- `results/processed/phase6b1_mean_sd.csv`
- `results/statistics/phase6b1_paired_tests.csv`
- `results/statistics/phase6b1_a4_effect_report.csv`
- `results/processed/phase6b1_metadata.json`

## What to report
For A1–A4, report mean ± SD over the same 10 seeds for detection and service metrics.

For A4 specifically, report:
- mean ± SD MTD rotations
- rotation rate
- unique target count / target coverage
- deception capture/redirect rate
- diverted attack traffic and diversion rate

Do not claim that these synthetic values are live SDN measurements. Phase 7 will move to real CIC-DDoS2019 and a secondary dataset; later Mininet/Ryu work will provide actual control-plane/network measurements.

## 6B.1 Test Fix

A stale Phase-6 regression test was removed from the Phase-6B.1 test suite. That test required `results/processed/phase6_mean_sd.csv`, an artifact produced only when the older Phase-6 experiment is run, so a fresh Phase-6B.1 checkout could fail even when the 6B.1 implementation was correct.

The replacement regression checks only Phase-6B.1-owned paths. The complete Phase-6B.1 suite now passes with 27 tests.
