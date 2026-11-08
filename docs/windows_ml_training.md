# Windows model training, inference and independent evaluation

This workflow is separate from the NSL-KDD model. It consumes the exact 19 numeric features declared in `windows_nids/schema.py`, produced from Sysmon Event ID 3 (Network Connect) and Event ID 22 (DNS Query) in 60-second per-process windows.

## 1. Prepare labelled feature windows

The live feature stream is unlabelled. Export it to a labelling template for one capture session:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\export_windows_label_template.py" `
  --input "D:\FUSE AI 201\Sysmon\data\windows_feature_stream.jsonl" `
  --output ".\data\windows_session_01_labels.csv" `
  --session-id "host01-session-01"
```

The template contains the original `snapshot_id`, timestamps, 60-second window size, process metadata and all 19 model features, plus blank `label` and `label_source` columns. Fill the two label columns only from independently verified ground truth. Examples of provenance include a documented benign capture session or a named, pre-collected and labelled Sysmon dataset/scenario. Do not label a window as malicious merely because its feature values look unusual. Do not execute malware to manufacture positive training examples; use instructor-approved or pre-collected, labelled security telemetry.

Use a new, unique `session_id` for each independently captured session. Rolling windows overlap by 50 seconds when emitted every 10 seconds, so individual rows are correlated. The training utility therefore splits by complete capture session rather than randomly splitting rows. Aim for at least five distinct sessions containing each class; the script refuses to split a class that occurs in only one session. Keep different hosts or collection runs separate where possible.

The current 70 KB local feature stream is useful as an initial baseline, but it does not contain verified malicious labels. It cannot, by itself, train a supervised benign-versus-malicious classifier. Also, do not feed the NSL-KDD 41-feature records into this trainer.

For pre-collected Sysmon event logs, convert the raw JSONL event session using the offline replay utility before exporting a label template. This uses the event timestamps (rather than the current wall clock) to reconstruct the same 60-second windows and 10-second cadence:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\build_windows_features_offline.py" `
  --input ".\data\approved_sysmon_session_01.jsonl" `
  --output ".\data\windows_session_01_features.jsonl" `
  --source-id "windows-pc-01" `
  --window-seconds 60 --step-seconds 10
```

The input must be a pre-collected Sysmon JSONL file in the collector's schema, with reliable event timestamps. This step extracts features only; it does not infer labels.

Then export the resulting feature windows into a blank label template:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\export_windows_label_template.py" `
  --input ".\data\windows_session_01_features.jsonl" `
  --output ".\data\windows_session_01_labels.csv" `
  --session-id "approved-session-01"
```

Repeat this process for each independently captured session, using a unique session ID and output file. Combine the completed labelled CSV files only after checking their feature columns and label provenance.

## 2. Train and evaluate the Windows model

Install project dependencies, then combine independently labelled session CSV files into one CSV with the same columns. Keep the raw labelled data local and do not commit it to the public repository.

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\train_windows_model.py" `
  --input ".\data\windows_labeled_features.csv" `
  --output-dir ".\artifacts" `
  --positive-label "Malicious"
```

Required columns are the 19 feature names plus `window_seconds`, `label`, `session_id` and `label_source`. `snapshot_id` is also required in exported templates and is used to detect duplicate rows. All rows must use the same 60-second window and pass the same feature consistency checks as live inference.

The trainer uses a class-weighted Random Forest with median imputation. It does not apply SMOTE to correlated rolling-window rows. A stratified group holdout is selected by capture session; only the training sessions are fitted, and the holdout sessions remain unseen by the estimator. The trainer writes:

- `artifacts/windows_nids_model.joblib`
- `artifacts/windows_nids_model.json` (schema, ordered features, classes, window size, provenance, training/holdout sessions and model hash)
- `artifacts/windows_nids_model.sha256`
- `artifacts/windows_nids_evaluation.json`
- `artifacts/windows_nids_holdout_predictions.csv`

The evaluation report includes accuracy, balanced accuracy, macro precision/recall/F1, weighted F1, MCC, confusion matrix and per-class metrics. For a binary task, `--positive-label` also calculates ROC-AUC and average precision. These are actual held-out metrics from the supplied labelled data; they must not be substituted with the historical NSL-KDD metrics.

## 3. Enable live inference

After the training command successfully creates both model files, restart the Windows stream processor with the model paths:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\run_windows_stream.py" `
  --input "D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl" `
  --features-output "D:\FUSE AI 201\Sysmon\data\windows_feature_stream.jsonl" `
  --predictions-output "D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl" `
  --source-id "windows-pc-01" `
  --window-seconds 60 `
  --step-seconds 10 `
  --model ".\artifacts\windows_nids_model.joblib" `
  --metadata ".\artifacts\windows_nids_model.json"
```

On startup the runner validates the metadata, exact feature order, estimator classes, 60-second training window and model SHA-256 checksum. If any contract differs, inference fails closed and feature collection continues without predictions. Prediction records include the model version and per-class estimator probabilities. The existing `confidence` field is the maximum class probability, not a calibrated probability of malicious activity.

## 4. Evaluate live predictions independently

For the final live evaluation, start a fresh capture session and use new, session-specific output files. Do not append this run to a previous prediction file or reuse any session used in model fitting or the internal holdout. For example, start the stream processor with the trained model and these output paths:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\run_windows_stream.py" `
  --input "D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl" `
  --features-output "D:\FUSE AI 201\Sysmon\data\windows_feature_eval01.jsonl" `
  --predictions-output "D:\FUSE AI 201\Sysmon\data\windows_predictions_eval01.jsonl" `
  --source-id "windows-pc-01" `
  --window-seconds 60 --step-seconds 10 `
  --model ".\artifacts\windows_nids_model.joblib" `
  --metadata ".\artifacts\windows_nids_model.json"
```

Stop the stream processor after collecting the evaluation session. Export a label template from that session-specific feature file, then label each row from ground truth and retain its `snapshot_id`:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\export_windows_label_template.py" `
  --input "D:\FUSE AI 201\Sysmon\data\windows_feature_eval01.jsonl" `
  --output ".\data\windows_live_holdout_labels.csv" `
  --session-id "host01-live-eval-01"
```

Then run:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\evaluate_windows_predictions.py" `
  --predictions "D:\FUSE AI 201\Sysmon\data\windows_predictions_eval01.jsonl" `
  --labels ".\data\windows_live_holdout_labels.csv" `
  --metadata ".\artifacts\windows_nids_model.json" `
  --output ".\artifacts\windows_nids_live_evaluation.json" `
  --positive-label "Malicious"
```

The evaluator matches predictions to independently labelled rows using `snapshot_id`, rejects mixed model versions, and refuses to evaluate sessions used for either model fitting or the internal holdout. It reports the number of matched, unlabelled and unmatched records alongside metrics. Unlabelled predictions are not counted as correct detections or false alarms.

## Scope and limitations

- This is a supervised classifier over the current network/DNS-only endpoint features. It can only learn the label distinctions supported by the supplied dataset; it is not a general malware detector.
- Sysmon Event ID 3 provides connection metadata and Event ID 22 provides DNS query metadata. These do not provide packet payload, byte counts, complete flow durations or all endpoint behaviours.
- Class probabilities from a Random Forest are not automatically calibrated risk probabilities.
- The live stream has no ground truth by default. Live accuracy, precision, recall, F1 and confusion matrices are available only after independently labelling matching snapshots.
- The model is for analyst triage and research evaluation, not automatic blocking or a sole security control.
- Only load joblib artifacts produced by a trusted local training run; joblib artifacts use Python pickle serialization.
