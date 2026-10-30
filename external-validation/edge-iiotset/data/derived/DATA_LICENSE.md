# Derived Edge-IIoTset feature sample

`features.csv.gz` and `predictions.csv.gz` are derived from Edge-IIoTset,
created by Mohamed Amine Ferrag and co-authors. The source dataset listing:
https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
identifies the dataset licence as Creative Commons Attribution-NonCommercial-
ShareAlike 4.0 International (CC BY-NC-SA 4.0):
https://creativecommons.org/licenses/by-nc-sa/4.0/.

Research paper: Ferrag et al., *Edge-IIoTset: A New Comprehensive Realistic
Cyber Security Dataset of IoT and IIoT Applications for Centralized and
Federated Learning*, IEEE Access (2022), DOI:
https://doi.org/10.1109/ACCESS.2022.3165809.

These files are an adaptation of a selected subset of the source captures:
packets were grouped into short directional flow records, 20 V4 features
were reconstructed, and the frozen retrained classifier was applied. Source
and destination IP addresses and ports were removed from the shared feature
file. The original selection plan and capture hashes are included alongside
the results. Attack labels are provisional and the subset is not a
representative sample of the full dataset.

These derived data files are offered under CC BY-NC-SA 4.0. This data notice
does not assign a licence to the rest of the repository or the model code.
