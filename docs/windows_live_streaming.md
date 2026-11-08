# Windows endpoint streaming and inference

This is a separate data path from the existing 41-feature NSL-KDD model. It consumes local Sysmon Event ID 3 (Network Connect) and Event ID 22 (DNS Query) JSONL records and emits process-instance feature snapshots over a sliding window.

## Data flow

1. `collect_sysmon.ps1` reads the local `Microsoft-Windows-Sysmon/Operational` log and appends Event ID 3/22 records to `sysmon_events.jsonl`. Run it in an elevated PowerShell window.
2. `scripts/run_windows_stream.py` tails that JSONL file, retains the latest 60 seconds of observations, and emits per-process snapshots every 10 seconds by default.
3. Snapshots are appended to `windows_feature_stream.jsonl`. They contain 19 numeric features plus window/source/process metadata. Raw IP addresses, raw DNS names, ProcessGuid and PIDs are not written to this feature stream.
4. When a trusted Windows model and matching JSON metadata are available, the runner can execute local inference with `--model` and `--metadata`.
5. Alternatively, the runner can send snapshots to the authenticated FastAPI `/windows/predict` route using `--api-url` and `WINDOWS_INGEST_API_TOKEN`. The API returns predictions but does not persist feature vectors.

## Run the stream processor on Windows

Use two terminals. In Terminal 1, run the Sysmon collector from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& "D:\FUSE AI 201\Sysmon\collect_sysmon.ps1"
```

In Terminal 2, from the repository checkout:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\run_windows_stream.py" `
  --input "D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl" `
  --features-output "D:\FUSE AI 201\Sysmon\data\windows_feature_stream.jsonl" `
  --predictions-output "D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl" `
  --source-id "windows-pc-01" `
  --window-seconds 60 `
  --step-seconds 10
```

The default is to start at the end of the existing event file, so older events are not relabelled as live. Use `--replay-existing` only for controlled debugging. Stop the processor with Ctrl+C.

## Prediction behavior before model training

No trained Windows model is included. Without `--model`/`--metadata`, or without the Windows API option, the runner writes feature snapshots only and explicitly reports that ML predictions are disabled. This is intentional; no placeholder or NSL-KDD prediction is substituted.

A trusted Windows model must be a fitted scikit-learn-compatible estimator implementing `predict` and `predict_proba`. Its metadata JSON must contain:

```json
{
  "schema_version": "windows-endpoint-v1",
  "model_version": "your-model-version",
  "feature_columns": ["... exact ordered feature names from windows_nids/schema.py ..."],
  "classes": ["Benign", "Suspicious"],
  "severity_mapping": {"Benign": "Low", "Suspicious": "Review"}
}
```

The actual `classes` must exactly match the fitted model's `classes_`. The feature-column list must exactly match the versioned schema. This prevents accidental use of the old NSL-KDD 41-feature model or a model trained against a different feature order. Only load model artifacts produced by a trusted local training pipeline; joblib model files use pickle internally.

For local inference, run:

```powershell
& ".\.venv\Scripts\python.exe" `
  ".\scripts\run_windows_stream.py" `
  --input "D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl" `
  --source-id "windows-pc-01" `
  --model ".\artifacts\windows_nids_model.joblib" `
  --metadata ".\artifacts\windows_nids_model.json"
```

For remote inference, set the token in the environment instead of putting it directly in shell history:

```powershell
$env:WINDOWS_INGEST_API_TOKEN = "YOUR_SECRET_TOKEN"
```

Then run the stream processor with `--api-url https://YOUR-API-HOST`. The API must have the matching Windows model artifact and metadata installed, with `WINDOWS_INGEST_API_TOKEN` configured on the server.

## API endpoints

- `GET /windows/schema`: returns the Windows feature contract and whether the configured model files exist.
- `POST /windows/predict`: authenticated batch inference; up to 100 snapshots per request. Requires `WINDOWS_INGEST_API_TOKEN` (or, for a single-producer prototype, the existing `LIVE_INGEST_API_TOKEN` fallback).

The endpoint returns predictions but does not write raw features to the database. The producer writes returned predictions to its local `windows_predictions.jsonl` file.

## Important limitations

- Sysmon Event ID 3 records connection metadata, not packet/byte counters, TCP flags, complete flow duration, or payload contents. Event ID 22 supplies DNS query metadata. These 19 features are endpoint behavior counts, not NSL-KDD features.
- The `Initiated` field is used only for TCP features. UDP is connectionless; UDP `Initiated` values are deliberately excluded from the model feature vector.
- A 60-second window emitted every 10 seconds is an overlapping sliding window. Successive snapshots are correlated and must not be treated as independent samples during train/test splitting. Split labelled data by time/session (and preferably by host) to reduce leakage.
- A model must be trained and independently evaluated on labelled Windows endpoint data before the predictions are shown as operational detections. Maximum class probability is not automatically a calibrated threat probability.
- The feature stream contains process names and a hashed process-instance identifier. Keep the raw Sysmon JSONL file local and access-controlled; it contains IP addresses, DNS names, PIDs, ProcessGuid and executable paths.
- The current Streamlit dashboard is not yet wired to Windows-specific prediction events. The NSL-KDD benchmark model and its evaluation results remain unchanged.
