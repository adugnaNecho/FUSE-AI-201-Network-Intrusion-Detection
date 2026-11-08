# Live NIDS telemetry integration

## Data categories

1. **Benchmark evaluation:** Results from public NSL-KDD validation and KDDTest+ splits. These remain fixed until the model is retrained and are not updated by live events.
2. **Uploaded CSV analytics:** Predictions from one file supplied by a user. These describe that upload and are not continuous monitoring.
3. **Live producer-submitted telemetry:** Predictions made after a trusted external producer sends records to the authenticated FastAPI endpoint. The API timestamps each accepted prediction and stores only source ID, predicted class, maximum class probability and severity.

## Critical compatibility requirement

The trained Random Forest expects all 41 features returned by `GET /schema`. Raw packets, Zeek logs, CICFlowMeter outputs, firewall counters and NetFlow/IPFIX records are not automatically equivalent to these features. Do not fill absent features with zeros or relabel columns. A validated feature extractor must produce the 41 fields with semantics consistent with the training data, or the model must be retrained on the live feature schema.

This repository does not capture packets and does not implement a validated 41-feature extractor. The producer client forwards compatible JSONL records only. The API cannot independently verify that a producer's source ID represents a real monitored network.

## Deploy the separate API service

Deploy `Dockerfile.api` as a separate service, with access to the trusted model artifact in `artifacts/`. Configure:

- `LIVE_INGEST_API_TOKEN`: a long random secret.
- `TELEMETRY_DATABASE_URL`: a persistent PostgreSQL URL.
- `PORT`: hosting platform port, if required.

The default SQLite database is for local testing only; hosted container filesystems may be ephemeral. Use HTTPS, restrict access, rotate exposed tokens, and do not commit credentials.

Verify `GET /health`, `GET /schema` (41 features), and `GET /docs`.

## Configure Streamlit

Add these TOML secrets in Streamlit Community Cloud:

```toml
LIVE_STATS_API_URL = "https://YOUR-API-HOST"
LIVE_STATS_API_TOKEN = "YOUR-SHARED-RANDOM-TOKEN"
```

The Live Monitoring tab polls the API every 10 seconds while active. If settings are absent or the API is unavailable, it displays an explanatory message. It does not substitute benchmark or uploaded-file values.

## Configure GitHub README refresh

In GitHub repository Settings → Secrets and variables → Actions, add `LIVE_STATS_API_URL` and `LIVE_STATS_API_TOKEN`. The `.github/workflows/update-live-readme.yml` workflow refreshes only the README section between `LIVE_NIDS_STATS` markers, approximately every 15 minutes. Scheduled jobs can be delayed. Use workflow_dispatch for a manual refresh.

## Connect a compatible producer

The input file must be JSON Lines: one JSON object per line containing all 41 feature names and compatible values. Set `LIVE_STATS_API_URL` and `LIVE_STATS_API_TOKEN` on the producer machine, then run:

```bash
python scripts/push_live_records.py --input /path/to/compatible_features.jsonl --source-id lab-gateway-01 --follow
```

The script forwards new lines appended to the file. It does not sniff packets, derive NSL-KDD features, or generate example events. Do not use the sample CSV as proof of live traffic.

## Metric interpretation

The live service displays accepted prediction counts, predicted class distribution, producer IDs and server-side timestamps. The API does not receive independent ground truth, so it cannot report live accuracy, precision, recall, F1-score or a confusion matrix. Predictions are not confirmed security incidents, and maximum class probability is not a calibrated threat probability.

The API deliberately does not persist raw feature vectors. Use privacy-reviewed sources and avoid sending payloads, credentials, personal data or unnecessary endpoint identifiers.
