# Group 19 | Machine Learning-Based Network Intrusion Detection

**Course:** FUSE AI-201 - AI Model Development and Implementation  
**Assignment:** Module 6 - AI Deployment, Monitoring, Support and Maintenance  
**Project:** Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification

> **Prototype status:** Source code, a CSV prediction interface, an optional API, training/export code, sample input, tests and deployment documentation are included. The trained model binary was not present in the files supplied for this packaging pass. Run the training/export step before expecting the app or API to return predictions. This package is not a production IDS and does not capture or block live traffic.

## 1. Project purpose

This prototype classifies an NSL-KDD connection record into one of five grouped categories: **Normal, DoS, Probe, U2R or R2L**. It uses a Random Forest classifier within an imbalanced-learn pipeline that applies SMOTENC, numerical imputation/scaling and categorical encoding.

The user-facing demonstration accepts a CSV file containing the 41 NSL-KDD input features and returns the predicted class, the model's maximum class probability (confidence score), a severity label and probabilities for all five classes. These confidence scores have not been calibrated and should not be interpreted as guaranteed probabilities of malicious activity.

This is a **benchmark-record classification proof of concept**. It is not a packet sensor, firewall, traffic blocker, live production monitoring service or guarantee of detection for modern/zero-day attacks.

## 2. Dataset and evaluation evidence

The supplied Module 5 notebook uses the public NSL-KDD benchmark (`KDDTrain+` and `KDDTest+`) retrieved through KaggleHub (`hassan06/nslkdd`). The recorded data shapes are 125,973 training rows and 22,544 independent test rows, with 41 model input features. Raw labels are mapped to the five classes above.

A stratified validation set is split from `KDDTrain+` using `test_size=0.1765` and `random_state=42`: 103,738 training rows and 22,235 validation rows. `KDDTest+` is held out until final evaluation. Preprocessing and SMOTENC remain inside the training pipeline. The 3-fold grid search recorded best CV Macro-F1 of 0.9019 and selected 250 trees, maximum depth 20 and minimum split 5.

| Metric | Held-out validation | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.8876% | 74.6274% |
| Macro precision | 97.1483% | 80.0803% |
| Macro recall | 99.4603% | 48.8729% |
| Macro F1 | 98.2503% | 51.5480% |

On `KDDTest+`, class recall was Normal 0.97, DoS 0.77, Probe 0.54, U2R 0.10 and R2L 0.06. The largest one-versus-rest false-positive rate was 0.408166 for Normal. All five success criteria shown in the notebook were marked **Fail** on the independent test set. The apparent validation/test gap is a key result and must be disclosed in any demonstration.

The notebook's timing experiment recorded 0.1190 ms per record for a batch of 1,000 records on its Colab runtime. This is a historical, machine-specific measurement and is not a service-level target. See [`docs/evaluation_and_limitations.md`](docs/evaluation_and_limitations.md) for the full interpretation and next experiments.

## 3. Repository contents

```text
.
├── app.py                       # Streamlit CSV prediction app
├── api.py                       # Optional FastAPI inference API
├── nids_core.py                 # 41-feature schema, validation and inference
├── train_model.py               # Reproducible training, evaluation and export
├── examples/sample_input.csv    # Constructed illustrative 41-feature input row
├── notebooks/
│   └── Group19_Module5_Implementation.ipynb
├── artifacts/
│   └── README.md                # Model artifact handoff instructions
├── data/
│   └── .gitkeep                # Raw benchmark files are not committed
├── docs/
│   ├── evaluation_and_limitations.md
│   ├── simulated_data_statement.md
│   ├── monitoring_support_maintenance.md
│   ├── module6_video_script.md
│   ├── submission_checklist.md
│   └── team_contributions.md
├── tests/
├── Dockerfile
├── requirements.txt
└── requirements-dev.txt
```

## 4. Run locally

Use Python 3.11. Keep Python and package versions aligned between model training and inference because serialized scikit-learn/joblib pipelines can be version-sensitive.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4.1 Obtain data and train/export the real model

Place the two NSL-KDD files here:

```text
data/KDDTrain+.txt
data/KDDTest+.txt
```

Or allow the script to retrieve the public `hassan06/nslkdd` dataset with KaggleHub (internet access required):

```bash
python train_model.py
```

The script trains the selected Random Forest + SMOTENC pipeline and creates:

- `artifacts/group19_final_nids_random_forest_pipeline.joblib`
- `artifacts/group19_nids_class_mapping.json`
- `artifacts/evaluation.json`
- `artifacts/model.sha256`

To repeat the notebook's three-fold, eight-setting GridSearchCV:

```bash
python train_model.py --tune
```

To log the run to a local MLflow tracking store:

```bash
pip install -r requirements-dev.txt
python train_model.py --mlflow
```

The script calculates metrics from the current execution. It does not insert fallback or illustrative model metrics.

### 4.2 Run the Streamlit prediction interface

After the trusted model artifact exists:

```bash
streamlit run app.py
```

Open the local URL printed by Streamlit. Download `examples/sample_input.csv`, upload it, and select **Predict intrusion class**. You can upload multiple connection records in one CSV. The input must contain all 41 feature columns; known benchmark metadata columns (`class`, `target`, `target_id`, `difficulty_level`) are ignored.

### 4.3 Run the optional FastAPI endpoint

```bash
uvicorn api:app --reload
```

- `GET /health` reports whether the model artifact is present.
- `GET /schema` returns the 41 required feature names.
- `POST /predict` accepts `{"records": [{...41 features...}]}` and returns class, confidence, severity and per-class probabilities.
- `/docs` provides interactive API documentation.

### 4.4 Run tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

The unit tests validate input schema handling, numeric conversion, error cases, prediction-output formatting with a deterministic test double and API request/schema behavior. The test double does **not** evaluate or replace the trained Random Forest.

## 5. Public access and prediction deployment

A public GitHub repository makes source code and documentation accessible; it does not by itself host a prediction service. To let an unauthenticated reviewer use the actual AI model:

1. Run `python train_model.py` in an internet-enabled environment with sufficient RAM and verify the generated `evaluation.json` against the expected notebook results.
2. Publish the trusted `.joblib` model as a versioned GitHub Release asset or in the repository if it is under GitHub's file-size limits. Publish its SHA-256 sidecar with it. Do not commit a model file you have not tested or one obtained from an untrusted source.
3. Deploy `app.py` from the public repository using Streamlit Community Cloud (or deploy `api.py` using a suitable host). Ensure the hosted runtime can access the exact versioned model artifact.
4. Open the deployed application in a signed-out/private browser session, upload the example CSV, run a prediction and record the real public URL for the submission. Streamlit Community Cloud requires the repository, branch and app entrypoint to be selected during deployment; its deployment guide describes this process.

If the model binary is larger than 100 MiB, use Git LFS or a model-artifact host and configure an authenticated, pinned, checksum-verified download. GitHub documents the 100 MiB ordinary Git file limit and Git LFS for larger files; Streamlit Community Cloud documents that repository LFS files are supported. Do not place credentials in source code, repository secrets exposed to the client, screenshots or the README. See [GitHub large-file guidance](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github) and [Streamlit Community Cloud deployment](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy).

**Current release caveat:** the model binary was absent from the supplied uploads and this packaging runtime had no outbound package/data download access. The source and app are prepared, but the model export and hosted prediction endpoint still need to be generated and verified in a network-enabled environment. Do not describe the app as publicly live until that check is complete.

## 6. Data disclosure

The training/evaluation dataset is public NSL-KDD benchmark data, not newly collected live traffic. The repository's sample CSV is a constructed illustrative row for exercising the interface. SMOTENC generates synthetic minority samples within model training only; validation and `KDDTest+` are not oversampled. Raw benchmark files are not redistributed by this repository. See [`docs/simulated_data_statement.md`](docs/simulated_data_statement.md).

## 7. Monitoring, responsible use and maintenance

The monitoring thresholds, shadow deployment, analyst workflows, fallback IDS and retraining cadence in the plan are **proposals**, not active services in this prototype. Because the model performs poorly on rare U2R/R2L classes in the independent test, predictions must not be used as the only security decision or to block traffic. See [`docs/monitoring_support_maintenance.md`](docs/monitoring_support_maintenance.md).

## 8. Contributors

The supplied Module 5 notebook lists five members. Named work-package assignments were not included in the supplied source. The group must complete and verify [`docs/team_contributions.md`](docs/team_contributions.md) before submitting the group portfolio/video.

## 9. Dataset reference

The notebook's download source is KaggleHub dataset `hassan06/nslkdd`. A public copy of NSL-KDD files is also documented at [jmnwong/NSL-KDD-Dataset](https://github.com/jmnwong/NSL-KDD-Dataset). Original reference: M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009. Verify the dataset host's terms before redistributing raw data.

## 10. License

The MIT license in this repository applies to the project code and documentation authored by Group 19. It does not grant rights to third-party datasets or components; their respective terms continue to apply.
