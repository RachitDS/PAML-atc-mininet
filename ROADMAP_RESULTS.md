# Accuracy roadmap results — 26 October 2026

Repository bundle: model artifacts, measured flow-feature vectors, event logs,
aggregate results and audit metadata are included. Original PCAPs and
per-packet observation logs remain in the local execution archive. Use the
current runner to regenerate full captures and repeat packet-level auditing;
`scripts/verify_published.py` reproduces the published paired detector scores.

On the same 19,431 fresh live request-flow records, the existing V4 model scored 94.84% accuracy and the retrained V4 model scored 98.12%: an improvement of 3.28 percentage points. False-positive rate fell from 40.82% to 0.53%. Attack recall changed from 100.00% to 97.93%.

The frozen retrained model achieved 98.99% accuracy and 99.42% F1 on the registered held-out lab-flow records. The previous model scored 99.27% and 99.58% on those identical records.
Fresh live MONITOR evaluation achieved 98.12% accuracy, 98.70% balanced accuracy, 98.91% F1, and 0.53% false-positive rate across ten new seeds.

The previous model is the existing V4 synthetic-trained model built on Ahalya’s work, not Ahalya’s original standalone model. The retrained model retains the V4 architecture and learns from measured generated Mininet traffic.

These results concern generated ICMP, UDP, and raw TCP SYN request streams inside Mininet. They are not public-dataset or real industrial-application accuracy. The old 37.84% trace used different collection, attribution, and scoring rules and is not a paired model comparison.

## Held-out comparison

| Model | Accuracy | Balanced accuracy | F1 | Recall | FPR |
|---|---:|---:|---:|---:|---:|
| Existing V4, synthetic-trained | 99.27% | 97.14% | 99.58% | 99.97% | 5.68% |
| V4 retrained on measured Mininet traffic | 98.99% | 99.43% | 99.42% | 98.85% | 0.00% |

## Paired detectors on the fresh monitoring trace

All three detectors below receive identical measured feature vectors. No detector changes the traffic in this comparison.

| Detector | Accuracy | Balanced accuracy | F1 | Recall | FPR |
|---|---:|---:|---:|---:|---:|
| Previous V4 | 94.84% | 79.59% | 97.13% | 100.00% | 40.82% |
| Retrained V4 | 98.12% | 98.70% | 98.91% | 97.93% | 0.53% |
| Fixed 200 PPS | 94.92% | 95.93% | 97.02% | 94.58% | 2.73% |

## Fresh live runs

| Mode | Decisions | Accuracy | F1 | Benign delivery | Attack delivery | ML loaded |
|---|---:|---:|---:|---:|---:|---|
| MONITOR | 19431 | 98.12% | 98.91% | 100.00% | 93.09% | True |
| NONE | 0 | N/A | N/A | 100.00% | 93.08% | False |
| FIXED | 4357 | 83.38% | 78.22% | 96.73% | 9.88% | False |
| PAML | 4207 | 94.96% | 93.71% | 98.78% | 8.63% | True |

MONITOR is the unbiased detector benchmark. Enforcing PAML and FIXED change which packets remain observable, so their mode-specific decision accuracy is conditional on observed traffic. Compare delivery results against NONE before attributing loss to defense. FIXED is a PPS-only policy. All paths forward independently of classifier execution.

## Reproducibility and measurement

- Audited collection: 90 scenarios, 329,208 observed requests, 16,678 feature rows, zero replay differences.
- 8 damaged/missing feature-log rows were reconstructed from intact packet observations and separately logged flow identities. `collection-audited/feature_recovery.json` identifies every recovered row; all other measured feature rows were checked against replay. Fresh validation logs use native WSL storage and serialized writes.
- Training seeds: 11,22,33,44,55,66; validation: 77,88; final held-out test: 99,111. Complete runs remain in one partition. The scaler and models fit only training data. Validation selects the model and threshold. Frozen hashes precede test scoring.
- Fresh seeds: 121,132,143,154,165,176,187,198,209,220. Profiles: 150 PPS × 1 attacker, 500 PPS × 3 attackers, 1000 PPS × 3 attackers. Each stream runs three seconds. Captures remain open until queues drain.
- One observation switch; directional identities include ports; ground truth comes from an experiment manifest. Responses and unrelated traffic are unscored. Unknown requests still receive predictions but do not enter confusion matrices.
- Classifier histories and persistence are independent per run and transport stream. Every emitted labeled flow has a unique ID and is scored once, including idle expirations.
- PCAPs at the observation point and PLC distinguish observation coverage from delivery. Capture drops, packet counts and packet-length histograms are audited. Observation-time feature replay verifies exact pipeline consistency.
- Controller feature times are processing/observation times, not hardware wire timestamps. Inference timings are amortized across a batch. Decision-local FlowMod submission timing excludes batch waiting and switch acknowledgement.
- `live_per_seed.csv` and `RESULTS.json` report variation across seeds and bootstrap intervals. Flow records within a run are correlated; they are not treated as independent experiments.

## Implementation

- Corrected flow attribution, unique IDs, switch/port identity and expiry handling.
- Cached independent ground truth, buffered logging, atomic snapshots and controller readiness checks.
- OpenFlow NORMAL forwarding, single-switch observation, clean NONE/FIXED paths and non-enforcing MONITOR.
- Batch RF inference with a sequential-equivalence regression test; serial tree prediction avoids the previous Eventlet/joblib deadlock.
- Zero-origin IAT handling now uses packet counts, preserving valid timestamp zero in both directions; regression checks cover clock-origin invariance. Measured run timestamps were positive, so this correction does not change the archived live feature values.
- The completed retrained model is the default for new controller/campaign launches; PAML_MODEL_DIR preserves an explicit model override. The registered validation already selected the retrained model explicitly.
- Seeded traffic generation with overlapping packet-size distributions across labels and explicit sender-buffer error counts.
- Fixed train/validation/test partitions and validation-only selection; prior models and supplied sources remain preserved.

## Remaining research validation

- Expand legitimate traffic to application transactions and unseen traffic generators. Current legitimate streams include low-rate and burst traffic, but do not model full ICS workloads.
- Run the full publication matrix of 30/60/90% attackers and 300/500/1000/2000 PPS across ten seeds and longer attacks. This first pass covers the registered smaller live matrix.
- Add external-dataset evaluation with compatible feature definitions; evaluate HTTP and Slowloris separately.
- Validate adaptive rate control, MTD address changes and deception end to end. This stage uses classifier-driven one-second drop rules; it makes no claims for those other mechanisms.

## Files

- `v4/models_live/training_report.json`: model selection, frozen hashes, held-out and per-protocol results.
- `collection-audited/`: training collection, PCAP references, packet observations and audit.
- `validation-{MODE}/`: fresh per-mode logs, metrics, captures and audits.
- `live_comparison.csv`, `live_per_seed.csv`, `RESULTS.json`: final comparisons.
- `v4/README_ROADMAP.md`, `validation_plan.json`, `run_campaign.sh`, `run_validation.sh`: reproducible workflow.
