# Attribution and project lineage

This repository extends the supplied PAML-ATC implementation and V4 iteration.
It does not claim that the foundational framework or all inherited code was
created by this iteration.

## Foundational work

Ahalya R, **PAML-ATC: A Predictive Adaptive Machine Learning-Based Automated
Traffic Controller for DDoS Defense in SDN-Enabled Industrial Control System
Networks**, SCOPE, Vellore Institute of Technology. The project documents and
original code supplied for this work identify Ahalya as the author. The paper
reports 96.85% accuracy and 96.07% F1 on its generated offline dataset.

The supplied V4 iteration retains that framework and adds its explicit
20-input schema, temporal flow histories and stateful detection. These V4
features are inherited by the current work rather than introduced here.

The underlying SDN/ICS ATC-MTD research includes Xingsheng Qin, Robin Doss,
Frank Jiang, Xingguo Qin and Biyue Long, **Securing ICS networks: SDN-based
Automated Traffic Control and MTD Defensive Framework against DDoS attacks**,
*Computer Communications* 241 (2025), 108252.
DOI: https://doi.org/10.1016/j.comcom.2025.108252

## Current additions

- Reliable directional flow identity and prediction-to-label attribution.
- Single-switch observation with forwarding independent of inference.
- Batched inference, buffered/native logging and capture accounting.
- Independent experiment labels and fixed train/validation/test groups.
- Retraining the V4 architecture on measured generated Mininet traffic.
- Audited fresh evaluation and comparisons on identical observed feature rows.

Original papers, submission PDFs and download archives are not republished
here. Their original local copies are preserved separately. Historical code
and phase documentation are retained for provenance; current validation
claims are limited to the scope documented in the repository README.
