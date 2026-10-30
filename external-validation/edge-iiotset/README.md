# Exploratory Edge-IIoTset replay

The frozen retrained V4 classifier was evaluated on an external packet-capture
sample from Edge-IIoTset. This is a fixed offline replay, not a live Mininet
experiment or a measurement of blocking. Labels are provisional and the
sample is not representative of the complete dataset.

| Metric | Retrained V4 |
|---|---:|
| Flow records | 76,525 |
| Accuracy | 99.84% |
| Balanced accuracy | 96.07% |
| False-positive rate | 7.87% |
| Attack recall | 100.00% |

**Do not present 99.84% as general accuracy.** The sample is 98.01% attacks;
predicting every record as an attack would score 98.01%. All 75,000 sampled
attack records contain one packet. The V4 duration floor assigns singleton
records a calculated 1,000,000 packets/second. The model falsely flagged
108 of 127 benign singleton records (85.04%), compared with 12 of 1,398
multi-packet benign records (0.86%). These groups may differ in other ways;
the comparison does not prove which feature caused the false alarms.

There are 1,525 selected normal records and 75,000 selected attack records.
Attack selection uses attack-scenario captures, protocol, destination and
flags; independent event labels were not verified for each packet. Capture
timestamps differ from controller observation times. Source and attack
captures come from different periods. This does not establish production
performance, attack-family classification or blocking effectiveness.

## Files and licensing

- `data/derived/`: redacted feature vectors and predictions, with the
  applicable [data licence and attribution](data/derived/DATA_LICENSE.md).
  The raw source/destination IP addresses and ports were removed.
- `data/source_manifest.json`: source capture names and hashes.
- `evidence/metrics.json`: full retrained-model metrics, including results by
  capture and flow size; `evidence/capture_inventory.json` records scan counts.
- `evaluation_plan.original.json`: the original plan written before scoring.
  That historical plan included a comparison with the previous V4 model; the
  published workflow evaluates only the retrained V4 model.
- `scripts/`: dataset download, packet inspection, replay and verification.

The dataset author's [Kaggle listing](https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot)
identifies the source as CC BY-NC-SA 4.0. The derived files carry the same
licence. See the [dataset paper](https://doi.org/10.1109/ACCESS.2022.3165809).
Raw PCAPs and downloaded archives are deliberately excluded from Git.

## Verify the published results

After the setup in the root README, from the repository root:

```bash
.venv-ml/bin/python external-validation/edge-iiotset/scripts/verify_results.py
PYTHONPATH="$PWD/v4" .venv-ml/bin/python -m pytest -q external-validation/edge-iiotset/scripts/test_fast_flow_table.py
```

The first command checks the frozen model hashes, recalculates predictions and
checks the confusion counts from the included redacted vectors. It does not
download captures, retrain, retune, or run Mininet. The tests compare optimized
flow expiry with the actual online table and compare replay scoring with the
deployed detector.

## Rebuild from source captures

The public file endpoint requires network access and availability. It supplies
four archives; uncompressed captures total about 764 MB. The download script
writes them only under ignored `data/archives/` and `data/pcap/` paths and
records local download hashes separately without altering the source manifest.

```bash
.venv-ml/bin/python external-validation/edge-iiotset/scripts/download_captures.py
.venv-ml/bin/python external-validation/edge-iiotset/scripts/replay_sample.py --output replay-new
```

The replay verifies capture and model hashes, then writes unredacted local
features and retrained-only predictions under ignored `results/replay-new/`.
It refuses to overwrite an existing run. The original sampling and capture
inventory are fixed so the same records can be reconstructed. For existing
captures elsewhere, set `EDGE_SOURCE_ROOT` to the earlier study's root; set
`EDGE_OUTPUT_ROOT` to choose a different output directory.
