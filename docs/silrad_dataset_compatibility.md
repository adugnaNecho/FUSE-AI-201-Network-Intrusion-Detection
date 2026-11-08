# SILRAD compatibility and labelled Windows-window preparation

## Why an audit is required

SILRAD is an event-level Sysmon dataset with labels documented as `0 = Goodware` and `1 = Ransomware`. The dataset README describes roughly 196,840 events (176,130 goodware and 20,710 ransomware), collected on isolated Windows 11 VMs. It also describes the benign and ransomware logs as stitched into a continuous stream.

The accompanying paper says the SILRAD pipeline uses fastText to turn Sysmon text into 100-dimensional vector representations. It discusses 52 default Sysmon fields and feature selection including TargetObject, Task, CallTrace, ParentImage and IntegrityLevel. These are not the same as this project's fixed 19 numerical features derived from Event ID 3 and Event ID 22 in 60-second per-process windows.

Consequently, the published `fasttext-*.csv` files must not be presumed to contain the raw timestamps, ProcessGuid/ProcessId, Image, protocol, destination IP/port and DNS query fields needed to reconstruct the live feature schema. Nor should a stitched event stream be presumed to retain independent capture-session identifiers. Inspect the actual archive first.

## 1. Inspect a downloaded SILRAD archive

Keep the downloaded research data outside Git and do not commit it to this repository. From the repository root:

    ./.venv/Scripts/python.exe ./scripts/inspect_sysmon_dataset.py --input "D:/FUSE AI 201/Sysmon/research/SILRAD-dataset.zip" --csv-name "fasttext-all-nofamily.csv" --report "./data/silrad-all-audit.json"

If the archive contains multiple CSVs, run the inspector once for each member, for example `fasttext-trainmodel.csv` and `fasttext-testmodel.csv`. The inspector prints column names, row count, event-ID counts, label counts, and which raw fields were found. It does not print raw event values.

The inspector reports `YES` only when it detects:
- Event-level labels;
- UTC/event timestamps;
- ProcessGuid, or ProcessId plus Image;
- Event ID 3 and Event ID 22 records;
- Event 3 protocol/destination fields and Event 22 DNS query field; and
- A populated explicit capture/session/run identifier for group-based evaluation.

A `NO` result means the published representation cannot safely be converted to the 19-feature process-window schema using the identified fields. In particular, numeric fastText vectors are not invertible into the original raw Sysmon fields. Do not guess, reconstruct or synthesize missing timestamps/process identifiers/network values. Seek a raw, appropriately labelled Sysmon export with documented capture provenance instead.

Even a `YES` result is only a candidate. Confirm the source field semantics, the label mapping, the granularity of the session identifier and whether a session corresponds to an independent capture before training.

## 2. Convert only if the source is demonstrably compatible

For a compatible raw CSV member:

    ./.venv/Scripts/python.exe ./scripts/build_labelled_windows_from_sysmon_csv.py --input "D:/FUSE AI 201/Sysmon/research/SILRAD-dataset.zip" --csv-name "raw-sysmon-events.csv" --output "./data/silrad_windows_labeled.csv" --report "./data/silrad-window-conversion-report.json" --source-id "silrad-public"

The converter requires the source event label mapping documented by SILRAD: `0` -> `Benign` (Goodware), `1` -> `Malicious` (Ransomware). It creates 60-second process windows at a 10-second cadence and preserves the source capture/session ID in `session_id`.

Only Event ID 3 and Event ID 22 contribute features. Process windows are labelled only when all eligible source events for that process in that window agree. If a window contains both labels, the entire window is excluded as ambiguous; no majority vote or feature-based label inference is used. Unknown labels or missing required raw fields stop conversion.

The output is private local training data. It is ignored by Git via `.gitignore`.

## 3. Training and evaluation restrictions

The existing trainer uses session-grouped holdout to reduce leakage from overlapping windows. Before training:
- Check class counts and the number of distinct capture sessions per class.
- Make sure each class occurs in at least two genuinely independent sessions; five or more is a preferable research target.
- Do not treat `fasttext-trainmodel.csv` and `fasttext-testmodel.csv` as independent capture sessions unless their documentation proves that they are grouped by capture/sample rather than arbitrary row or stream partitions.
- Do not relabel the 1,404 local Session 01/02 snapshots automatically. They remain unlabelled until their normal-use status is reviewed and documented.
- The SILRAD source is specifically a ransomware dataset. A resulting classifier should be described as a ransomware-oriented Windows telemetry model, not a general detector for every intrusion or malware family.

Once the labelled CSV has sufficient independent session coverage, the existing Windows trainer can be run:

    ./.venv/Scripts/python.exe ./scripts/train_windows_model.py --input "./data/windows_labeled_features.csv" --output-dir "./artifacts" --positive-label "Malicious"

The trainer will still stop if required columns, labels or capture groups are missing. Do not publish local Sysmon data, labelled endpoint traces, or trained artifacts containing sensitive operational information.

## Sources

- JamilIsp, SILRAD dataset README and archive description: https://github.com/JamilIsp/SILRAD-dataset
- Ispahany et al., *A Sysmon Incremental Learning System for Ransomware Analysis and Detection*, sections 3.2–3.3 and 4.4: https://doi.org/10.21203/rs.3.rs-7543943/v1
- Zenodo record: https://doi.org/10.5281/zenodo.17104902
