# How this work builds on Ahalya and the supplied V4 iteration

The current model builds on Ahalya's project and the supplied V4 additions.
It retains the V4 random-forest and temporal-feature architecture. The new
work corrects the live pipeline and retrains that architecture on measured,
generated Mininet traffic. It does not introduce a new detection algorithm.

| Stage | Role | Evidence |
|---|---|---|
| Ahalya's original project | Starting PAML/ATC research and implementation | See `ATTRIBUTION.md`; original documents and execution archives are preserved locally |
| Supplied V4 iteration | Existing additions: 20 inputs comprising 8 base and 12 temporal features, per-stream histories and persistence | Existing synthetic-trained model in `v4/models/` and inherited phase documentation |
| Current engineering additions | Independent flow identities and labels, one observation switch, reliable capture/logging, batched inference, clean baselines, separate train/validation/test groups | Current `v4/` source and root experiment scripts |
| Retrained V4 model | Same model family and feature schema, fitted on measured lab traffic; configuration chosen using validation only | `v4/models_live/` and its `training_report.json` |

“Previous model” in the comparison means the existing V4 model trained using
its synthetic calibration generator, as reproduced in the 25 October run.
It does not mean Ahalya's original standalone model.

“Retrained model” means V4 trained from packet observations collected during
real execution of Mininet on this laptop. These packets are generated lab
traffic. They are not real industrial-network transactions or an external
public dataset.

Both models were evaluated on the same 3,279 untouched measured flow records:

| Metric | Existing V4 | Retrained V4 |
|---|---:|---:|
| Accuracy | 99.27% | 98.99% |
| Balanced accuracy | 97.14% | 99.43% |
| F1 | 99.58% | 99.42% |
| Benign flows falsely flagged | 23/405 | 0/405 |
| Attack flows missed | 1/2,874 | 33/2,874 |

This is a trade-off between false alarms and attack recall. The selection
objective was registered before testing and used validation data only. It
is not a raw-accuracy increase over the previous V4 model on these records.

The frozen retrained model also completed ten fresh live seeds. On the same
19,431 fresh request-flow records, the existing V4 model achieved 94.84%
accuracy and the retrained V4 achieved 98.12%. False-positive rate fell from
40.82% to 0.53%; attack recall changed from 100% to 97.93%.

The fresh matrix includes higher legitimate bursts and a 500 PPS attack
profile absent from collection. It differs from the earlier held-out record
comparison above. All configurations remained frozen during fresh testing.

Final results and limitations are in `ROADMAP_RESULTS.md`. Comparisons with
Ahalya's original offline 96.88% or the review's earlier V2 live 60.71% must
acknowledge the different pipeline, data and evaluation conditions.
