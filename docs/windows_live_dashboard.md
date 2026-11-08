# Local Windows endpoint prediction dashboard

The Streamlit application has a dedicated **Windows Endpoint Monitoring** tab. It is separate from the NSL-KDD **Live Monitoring** tab.

## Local file integration

By default, the tab reads:

    D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl

It refreshes every 10 seconds and displays validated prediction records written by scripts/run_windows_stream.py: process name, predicted class, severity, maximum class probability, model version, and UTC window time. It includes class/severity summaries, a time series, recent prediction rows, and CSV export.

Override the path with the WINDOWS_PREDICTIONS_PATH environment variable before starting Streamlit:

    $env:WINDOWS_PREDICTIONS_PATH = "D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl"
    & ".\.venv\Scripts\python.exe" -m streamlit run app.py

The dashboard checks that the configured Windows model artifact and metadata exist, match the 19-feature schema, and have a matching SHA-256 checksum. The stream processor performs the full estimator load and class/window validation when it starts.

## Start local inference

First ensure that a genuine Windows-specific model has been trained from independently verified labelled sessions. Then, from the repository root, start the Sysmon collector in an elevated PowerShell window and run the processor in a second window:

    & ".\.venv\Scripts\python.exe" ".\scripts\run_windows_stream.py" --input "D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl" --features-output "D:\FUSE AI 201\Sysmon\data\windows_feature_stream.jsonl" --predictions-output "D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl" --source-id "windows-pc-01" --window-seconds 60 --step-seconds 10 --model ".\artifacts\windows_nids_model.joblib" --metadata ".\artifacts\windows_nids_model.json"

Then launch the Streamlit app locally:

    & ".\.venv\Scripts\python.exe" -m streamlit run app.py

Open the local Streamlit URL and select **Windows Endpoint Monitoring**. Keep the collector, stream processor, and Streamlit app running.

## Hosted dashboard limitation

Streamlit Community Cloud cannot read a file stored on a user's personal Windows computer. The local-file view is therefore intended for Streamlit running on the same Windows computer as the prediction file. Displaying Windows predictions on the public hosted dashboard requires a separately secured remote prediction-ingestion and storage service, plus access controls and deployment configuration. Do not expose a local JSONL file or API token publicly.

## Interpretation

- No model artifact or metadata means there are no Windows ML predictions; feature snapshots are not predictions.
- A present prediction file with zero records means the inference processor has not written any predictions yet.
- A class label is a model classification, not a confirmed incident.
- Maximum class probability is not a calibrated threat probability.
- Live precision, recall, F1, and false-positive rates require independently labelled ground truth.
- Do not use Windows labels or metrics as substitutes for the existing NSL-KDD benchmark results.
