# PAML-ATC Mininet

An extension of Ahalya R's PAML-ATC work with the supplied V4 temporal detector,
retraining on measured Mininet traffic, and reproducible SDN DDoS evaluation
using Ryu and Open vSwitch. See [ATTRIBUTION.md](ATTRIBUTION.md) for the lineage.

The implementation retains the V4 random-forest architecture: 8 base and 12
temporal inputs, per-stream history, and persistence. This iteration adds
correct flow-to-label attribution, one observation switch, batched inference,
independent experiment ground truth, buffered logging, and clean baselines.

## Verified results

Both detectors below received the **same 19,431 fresh request-flow records**
from generated live Mininet traffic. Configuration and model weights were
frozen before this fresh evaluation.

| Metric | Existing synthetic-trained V4 | Retrained V4 |
|---|---:|---:|
| Accuracy | 94.84% | **98.12%** |
| Balanced accuracy | 79.59% | **98.70%** |
| Precision | 94.42% | **99.92%** |
| Attack recall | 100.00% | 97.93% |
| F1 | 97.13% | **98.91%** |
| False-positive rate | 40.82% | **0.53%** |

The accuracy increase is **3.28 percentage points**. Fewer false alarms come
with a reduction in attack recall. These are generated lab request streams,
not production-network or public-dataset results. The earlier review's V2
60.71% score used different measurement and labeling conditions and is not
the controlled baseline above.

The separate held-out collection comparison is also retained: existing V4
99.27% accuracy versus retrained V4 98.99%, with FPR 5.68% versus 0.00%.
It covers different traffic conditions from the fresh evaluation above.

**Validation:** 55 tests passed; 90 collection scenarios; 360 fresh live
scenarios across MONITOR, NONE, FIXED and PAML. Accepted captures had zero
kernel drops, and recorded features/predictions were independently replayed.

With enforcement enabled, legitimate delivery was 98.78% and attack delivery
8.63%, compared with 100.00% and 93.08% for NONE. Enforcement changes which
packets remain observable; use MONITOR for the detector benchmark and the
per-mode captures for network-policy evaluation.

- [Full results and limitations](ROADMAP_RESULTS.md)
- [Model lineage](MODEL_LINEAGE.md)
- [Registered validation plan](validation_plan.json)
- [Machine-readable results](RESULTS.json)
- [Per-seed results](live_per_seed.csv)
- [Final verification record](evidence/final-verification.json)

## Setup

Tested on Ubuntu 24.04 under WSL2 with Python 3.12, Mininet 2.3.0,
Open vSwitch 3.3.9 and Ryu 4.34. Run Linux commands inside Ubuntu/WSL.

```bash
git clone https://github.com/RachitDS/PAML-atc-mininet.git
cd PAML-atc-mininet
bash scripts/setup_linux.sh
```

The setup script creates `.venv-ml` and `.venv-ryu`, installs the recorded
package versions, and applies the Ryu/Eventlet compatibility workaround.
Pretrained model artifacts are included; retraining is not required to run
the detector. The model files match the package versions in the lock files.

## Tests and published-result verification

```bash
cd v4
../.venv-ryu/bin/python -m pytest -q
cd ..
.venv-ml/bin/python scripts/verify_published.py
```

The second command checks the frozen model hashes and reproduces the paired
detector scores from the included measured feature vectors. Original PCAPs
and per-packet observation logs remain in the local execution archive rather
than Git. The original audit metadata is included. Regenerate captures to
repeat the complete packet-level audit.

## Fresh live runs

The traffic generators target private Mininet addresses in the included
isolated topology. The modes are:

| Mode | Behavior |
|---|---|
| MONITOR | Predict without enforcing; switch forwarding remains independent |
| NONE | Direct forwarding, with no model loading or inference |
| FIXED | PPS threshold policy, with no model loading or inference |
| PAML | Frozen detector plus one-second drop rules |

```bash
sudo bash run_campaign.sh my-smoke MONITOR 121 '300:3'
sudo .venv-ml/bin/python audit_campaign.py outputs/my-smoke
```

Profiles use `PPS:attacker_count`. A smoke campaign covers ICMP, UDP and raw
TCP SYN; each stream runs for three seconds. Outputs are written beneath
`outputs/`, and existing campaign names are protected from overwriting.

To repeat the ten-seed, four-mode validation:

```bash
sudo bash run_validation.sh
```

To use existing environments instead of the repository defaults:

```bash
sudo env PAML_PYTHON=/path/to/ml/bin/python \
  PAML_RYU_MANAGER=/path/to/ryu/bin/ryu-manager \
  bash run_campaign.sh another-smoke MONITOR 121 '300:3'
```

The completed retrained model is selected by default. `PAML_MODEL_DIR`
explicitly selects another model folder.

## Training

`v4/train_live.py` fits on seeds 11/22/33/44/55/66, selects configuration on
77/88, then freezes artifacts before evaluating 99/111. Complete runs stay
in one partition. The scaler is fitted on training data only.

The saved training/validation/test records and training report are in
`v4/models_live/`. The script requires a fully audited collection and refuses
to retune the already evaluated output folder. Future iterations need new
untouched test runs; the included test results are not tuning data.

## Scope and remaining work

Current live coverage is ICMP, UDP and raw TCP SYN requests to the PLC, using
150 PPS with one attacker and 500/1000 PPS with three attackers over ten fresh
seeds. Replies are unscored; unknown requests are classified but have no
ground truth in the confusion matrix. Ground-truth labels and addresses are
metadata, not model inputs.

The full 30/60/90% attacker and 300/500/1000/2000 PPS matrix, longer attacks,
realistic ICS application transactions, HTTP/Slowloris, and external datasets
remain to be evaluated. Adaptive rate control, MTD and deception components
are retained from the project lineage but are not validated by this
classifier/drop-enforcement experiment. Historical phase READMEs describe
earlier versions; use this README for the current workflow.
