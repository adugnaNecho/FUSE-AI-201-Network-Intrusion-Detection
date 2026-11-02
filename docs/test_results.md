# Group 19 — Module 6 Test and Demonstration Evidence

**Project:** Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification  
**Group:** Group 19 | FUSE AI-201  
**Run period:** November 2–3, 2026 (as reported by the group)

## 1. Training and model export

The group reported a successful `python train_model.py` execution. KaggleHub downloaded and extracted the public NSL-KDD dataset. The training script exported the serialized model pipeline, class mapping, evaluation JSON and SHA-256 sidecar under `artifacts/`. The group reported the model file size as approximately 8.6 MB and confirmed that it was committed to the public GitHub repository.

## 2. Latest model evaluation

| Metric | Validation | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.89% | 74.62% |
| Macro precision | 97.17% | 79.35% |
| Macro recall | 99.46% | 48.71% |
| Macro F1 | 98.26% | 51.51% |

Independent-test class recall: Normal 97.28%, DoS 76.57%, Probe 53.52%, U2R 8.96%, R2L 7.20%. These results demonstrate a material generalization gap and weak recall for U2R and R2L.

## 3. Automated software tests

The final source-package QA reported:

```text
python -m pytest -q
29 passed
```

The group should repeat this command in the local Windows environment after copying the final package. Tests validate software behavior and dashboard data handling; they do not establish predictive performance.

## 4. Streamlit prototype demonstration

**Public application:** https://group19-network-intrusion-detection.streamlit.app/  
**Public repository:** https://github.com/adugnaNecho/Group19-network-intrusion-detection

The group reports that the hosted application installed its dependencies, accepted a CSV upload and generated a prediction. The supplied screenshot records one sample row with predicted class DoS, displayed maximum class probability 1.00, severity High and per-class probability outputs. The screenshot demonstrates the upload-to-prediction interaction for that row only; it does not establish prediction correctness or calibration.

The supplied dashboard screenshots show independent-test metric cards, grouped validation/test bars, class-wise metrics, the 5 × 5 confusion matrix, and a one-versus-rest FPR chart. Uploaded-record analytics require a 41-feature input CSV to be uploaded in the Prediction tab and scored.

## 5. FPR chart hotfix and cloud verification

The group pushed the FPR chart data-schema/fallback hotfix as GitHub commit `8941226`. The earlier Cloud screenshot showed an unhandled `ValueError` in Plotly Express at the FPR chart. The updated source uses explicit FPR columns and a table fallback for handled Plotly rendering errors. The final Streamlit Community Cloud rebuild and post-hotfix smoke test still require confirmation. Before submission, confirm the hosted app is running commit `8941226` and review **Manage app → Logs** if the issue remains.

## 6. Evidence files

- `docs/assets/streamlit_prediction_demo.png` — hosted interface screenshot showing a one-record prediction.
- `docs/assets/dashboard_grouped_comparison.png` — grouped validation/test comparison screenshot.
- `docs/assets/dashboard_class_metrics_confusion.png` — class-wise metrics and confusion-matrix screenshot.
- `docs/assets/dashboard_fpr_uploaded_analytics.png` — FPR and uploaded-record analytics screenshot captured before the final hotfix.
