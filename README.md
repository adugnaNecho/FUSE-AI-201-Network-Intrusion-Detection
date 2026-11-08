# Group 19 | Machine Learning-Based Network Intrusion Detection

**Course:** FUSE AI-201 — AI Model Development and Implementation  
**Assignment:** Module 6 — AI Deployment, Monitoring, Support and Maintenance  
**Project:** Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification

> **Live Streamlit prototype:** https://fuse-ai-201-network-intrusion-detection.streamlit.app/  
> **Public GitHub repository:** https://github.com/adugnaNecho/FUSE-AI-201-Network-Intrusion-Detection  
> **Source hotfix commit:** `8941226` — FPR chart data handling and table fallback.

**Prototype scope:** The application retains the NSL-KDD benchmark and uploaded-CSV workflows, and now includes an optional Live Monitoring interface for predictions submitted by an authenticated external producer. The application does not capture packets or transform raw traffic into the model's 41-feature schema. Live monitoring remains inactive until a compatible producer and separate persistent telemetry API are deployed. The maximum class probability is not a calibrated guarantee.

## Live telemetry statistics

<!-- LIVE_NIDS_STATS_START -->

### Live telemetry statistics

> No live telemetry has been connected yet. This section will be populated only from timestamped predictions received by the authenticated external telemetry API. It is separate from the NSL-KDD benchmark results below.

**Status:** Waiting for a compatible live producer.  
**Live data requirement:** An external producer must provide all 41 model features. Raw packets, Zeek logs, and CICFlowMeter records are not automatically compatible with the current NSL-KDD model.

The API stores prediction summaries, not raw feature rows. It cannot calculate live accuracy without independently supplied ground-truth labels, and it cannot independently verify the producer's traffic-capture provenance.

<sub>Once configured, GitHub Actions refreshes this block approximately every 15 minutes. Scheduled jobs may be delayed. The Streamlit Live Monitoring tab polls the API every 10 seconds while the app session is active.</sub>

<!-- LIVE_NIDS_STATS_END -->

## 1. Project purpose

The prototype classifies connection-level records into five classes: **Normal, DoS, Probe, U2R, and R2L**. It uses a Random Forest model in an imbalanced-learn pipeline with SMOTENC, numeric imputation/scaling, and categorical imputation/one-hot encoding.

The Streamlit interface accepts a CSV containing the 41 NSL-KDD model features and returns a predicted class, maximum class probability (displayed as confidence), threat-severity label, and probabilities for all five classes. It provides a sample input download and prediction-results CSV download. The Analytics Dashboard presents benchmark results and uploaded-record summaries.

## 2. Dataset and evaluation

Training and benchmark evaluation use public NSL-KDD files (`KDDTrain+` and `KDDTest+`) retrieved through KaggleHub (`hassan06/nslkdd`). The model uses 41 connection features and consolidates detailed labels into five target classes. The dataset contains 125,973 training records and 22,544 independent test records.

A stratified validation split is created from `KDDTrain+` with `test_size=0.1765` and `random_state=42`: 103,738 training records and 22,235 validation records. `KDDTest+` is reserved for final evaluation. SMOTENC is part of the fitting pipeline and is used only on training data.

### Latest reported training run (November 2–3, 2026)

| Metric | Validation | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.89% | 74.62% |
| Macro precision | 97.17% | 79.35% |
| Macro recall | 99.46% | 48.71% |
| Macro F1 | 98.26% | 51.51% |

Independent-test recall by class:

| Class | Recall |
|---|---:|
| Normal | 97.28% |
| DoS | 76.57% |
| Probe | 53.52% |
| U2R | 8.96% |
| R2L | 7.20% |

The validation-to-test gap is substantial. U2R and R2L recall are especially low. The prototype must not be used as the sole security control or for automatic blocking.

## 3. Public prototype

**Application:** https://fuse-ai-201-network-intrusion-detection.streamlit.app/ 
**Repository: ** https://github.com/adugnaNecho/FUSE-AI-201-network-intrusion-detection

The group reports that the hosted application accepted a CSV upload and generated a prediction. The supplied screenshot shows one illustrative record classified as **DoS**, with displayed maximum class probability **1.00** and severity **High**. This demonstrates the interface flow for that example only; it does not prove that the prediction is correct or that the score is calibrated.

### Application workflow

1. Open the Streamlit application.
2. Download the sample 41-feature CSV or prepare a CSV with the complete input schema.
3. Upload the CSV.
4. Select **Predict intrusion class**.
5. Review predicted class, maximum class probability, severity, and class probabilities.
6. Download prediction results as CSV.

## 4. Analytics dashboard

The dashboard includes:
- Grouped validation-versus-independent-test bars on a 0–100% axis.
- Accuracy, macro precision, macro recall, and macro F1 cards.
- Class-wise precision, recall, F1, and support when present in `artifacts/evaluation.json`.
- The measured 5 × 5 confusion matrix and one-versus-rest FPR when present in the evaluation artifact.
- Consistent class order: Normal, DoS, Probe, U2R, R2L.
- Integer support counts and percentage-formatted FPR displays.
- Uploaded-record class/severity counts, traffic-feature profiles by record order, and maximum class probabilities after prediction.
- A separate **Live Monitoring** tab that polls the authenticated telemetry API every 10 seconds when configured. It reports producer-submitted predictions only and never substitutes benchmark or uploaded-file statistics for live readings.
- A separate **Windows Endpoint Monitoring** tab that reads the local Sysmon prediction JSONL file every 10 seconds when a trained Windows-specific model is active. This local view is distinct from the NSL-KDD Live Monitoring tab and does not make a personal Windows file visible to Streamlit Community Cloud.

Live telemetry counts are not benchmark metrics. The API records server timestamps, producer ID, predicted class, maximum class probability, and severity; it deliberately does not persist raw feature vectors. Since no ground-truth labels are supplied with the live stream, the app does not report live accuracy, precision, recall, F1-score, or a live confusion matrix.

The dashboard does not fabricate a confusion matrix or class-level values if they are absent from the source artifact. If Plotly cannot render the FPR chart, the app falls back to a measured FPR table. NSL-KDD has no timestamp in the 41-feature schema, so uploaded-record plots use record order, not time. See `docs/analytics_dashboard_guide.md`, `docs/live_telemetry_setup.md`, and `FPR_CHART_HOTFIX.md`.

The Windows Endpoint Monitoring tab reads a local prediction file by default at `D:\\FUSE AI 201\\Sysmon\\data\\windows_predictions.jsonl`; configure `WINDOWS_PREDICTIONS_PATH` to override it. Run Streamlit on the same Windows computer as the file. The hosted cloud app cannot access a personal Windows filesystem. See `docs/windows_live_dashboard.md` for setup.

## 5. Model and implementation

The final estimator is a Random Forest inside an imbalanced-learn pipeline. The reported selected configuration used 250 trees, maximum depth 20, and minimum split 5. SMOTENC handles mixed categorical/numeric minority examples during fitting; numeric values are imputed and standardized; categorical fields are imputed and one-hot encoded. The complete preprocessing/model pipeline is exported as a single joblib artifact.

The optional FastAPI API provides `/health`, `/schema`, and `POST /predict`; Docker packaging is included. FastAPI and Docker are optional implementation paths and are not claimed as separately hosted public services.

## 6. Installation and local use

The group's tested local environment is **Python 3.12.3**. Keep core model dependencies aligned with the versions used to serialize the model.

```bash
python -m venv .venv
# Windows Git Bash: source .venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Train and export (optional)

Place `KDDTrain+.txt` and `KDDTest+.txt` in `data/`, or allow KaggleHub to retrieve the public dataset:

```bash
python train_model.py
```

This exports the model pipeline, class mapping, evaluation report, and SHA-256 sidecar under `artifacts/`.

### Run Streamlit

```bash
streamlit run app.py
```

Open the local URL printed by Streamlit, normally `http://localhost:8501`.

### Run optional FastAPI

```bash
uvicorn api:app --reload
```

Interactive API documentation is available at `/docs` while the API is running locally.

### Run tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

**Final source-package QA reported:** 29 tests passed. Rerun this command in the team's Windows environment after copying final files; software tests are not a substitute for predictive-performance evaluation.

## 7. Model artifacts

The trained `.joblib` pipeline, class mapping, `evaluation.json`, and SHA-256 sidecar are stored in the repository's `artifacts/` directory. This directory is the canonical model-artifact location. Load joblib files only from a trusted source.

## 8. Deployment and maintenance status

The Streamlit app URL is listed above. GitHub stores source and model artifacts; Streamlit Community Cloud hosts the interactive app. The FPR chart hotfix was committed as source commit `8941226`. The Live Monitoring interface is implemented, but it will show a configuration message until a separate FastAPI telemetry service, persistent PostgreSQL database, Streamlit secrets, GitHub Actions secrets, and a compatible external producer have been configured. See `docs/live_telemetry_setup.md` for deployment and verification steps.

The monitoring, drift detection, retraining, shadow deployment, fallback IDS, privacy and support processes in `docs/monitoring_support_maintenance.md` remain proposed plans for a future controlled pilot. The new telemetry code provides an ingestion and display path, but it does not capture packets or supply the missing live 41-feature extraction component. A compatible producer must be connected before the service can report live network-derived predictions.

## 9. Data disclosure and responsible use

Training/evaluation use public NSL-KDD benchmark data, not newly collected live operational traffic. The included sample CSV is a constructed illustrative input. SMOTENC generates synthetic minority-class observations during training only; validation and independent `KDDTest+` rows are not oversampled. Raw benchmark files are not redistributed in this repository.

Do not upload confidential network records or sensitive network details to the public demonstration. The prototype should not block traffic or be used as the sole basis for security decisions. High-impact predictions require independent analyst review.

## 10. Team and Canvas submission

Five members contribute to this assignment and their roles are presented in `docs/team_contributions.md`. The 8–9-minute video script is in `docs/module6_video_script.md`; the group must record and upload the actual video.

## 11. Dataset attribution

The notebook uses KaggleHub dataset `hassan06/nslkdd`. A public NSL-KDD mirror is documented at https://github.com/jmnwong/NSL-KDD-Dataset. Original reference: M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009. Review dataset-host terms before redistributing raw benchmark files.
