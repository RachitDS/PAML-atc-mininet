"""Small Phase-6B.3 packet-accounting sanity demo."""
from phase6b3_experiment import run_seed

rows = run_seed(0)
print("=== PAML-ATC V2 Phase-6B.3 Packet Accounting Demo ===")
for r in rows:
    print(
        f"{r['configuration']}: offered={r['total_offered_packets']:,} "
        f"delivered={r['total_delivered_packets']:,} "
        f"overall_pdr={r['overall_pdr']:.6f} "
        f"attack_delivered={r['attack_delivered_packets']:,} "
        f"attack_diverted={r['attack_diverted_packets']:,}"
    )
