# V4 changelog

1. Resolved the previous 20-vs-29 feature-count ambiguity.
2. Added an exact 20-feature V4 schema.
3. Added shared temporal feature builder for offline and online paths.
4. Rebuilt calibration data from packet-level short-flow aggregation.
5. Added ten-seed calibration results and threshold selection.
6. Added live feature-vector logging.
7. Added training-vs-live KS/SMD diagnostics.
8. Reworked controller latency to a single `monotonic_ns()` timebase with raw timestamp evidence.
9. Reduced inference overhead by avoiding a pandas DataFrame per PAML decision.
10. Preserved real Mininet/Ryu/ATC/MTD/deception evaluation instead of substituting synthetic live scores.
