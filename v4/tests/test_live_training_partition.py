import pandas as pd
from train_live import partition, PARTITIONS


def test_entire_runs_and_seeds_stay_in_one_partition():
    rows=[]
    for seeds in PARTITIONS.values():
        for seed in seeds:
            for proto in ['ICMP','UDP','TCP']:
                for label in [0,1]:
                    rows.append(dict(seed=seed, protocol=proto, label=label, run_id=f'{seed}-{proto}'))
    parts=partition(pd.DataFrame(rows))
    for a, left in parts.items():
        for b, right in parts.items():
            if a!=b:
                assert not set(left.run_id)&set(right.run_id)
                assert not set(left.seed)&set(right.seed)
