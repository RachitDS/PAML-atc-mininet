# Current accuracy workflow

See the [repository README](../README.md), [results](../ROADMAP_RESULTS.md),
and [attribution](../ATTRIBUTION.md).

From the repository root, after setup:

```bash
sudo bash run_campaign.sh my-smoke MONITOR 121 '300:3'
sudo .venv-ml/bin/python audit_campaign.py outputs/my-smoke
```

The completed retrained model in `models_live/` is selected by default.
`PAML_MODEL_DIR` provides an explicit override. NONE and FIXED skip model
loading. MONITOR predicts without enforcement. PAML applies one-second drops.

Ground truth belongs to the experiment manifest, not the model input. The
declared task scores request-direction streams to the PLC; replies remain
unscored. Unknown requests receive predictions without entering confusion
matrices. Every emitted labeled window retains its unique flow identity.

Timestamps measure controller observations rather than hardware wire time.
Inference cost is amortized over batches. Decision-local submission timing
excludes batch waiting and switch acknowledgement.
