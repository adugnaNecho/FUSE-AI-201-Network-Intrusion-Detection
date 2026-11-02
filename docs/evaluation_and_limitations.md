# Evaluation Results and Limitations

**Project:** Group 19 — Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification  
**Dataset:** NSL-KDD (`KDDTrain+` / `KDDTest+`)  
**Model:** Random Forest + SMOTENC pipeline  
**Public application:** https://group19-network-intrusion-detection.streamlit.app/

## Latest reported run

| Metric | Validation | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.89% | 74.62% |
| Macro precision | 97.17% | 79.35% |
| Macro recall | 99.46% | 48.71% |
| Macro F1 | 98.26% | 51.51% |

Independent test set: 22,544 records.

| Class | Precision | Recall | F1-score | Support |
|---|---:|---:|---:|---:|
| Normal | 64.30% | 97.28% | 77.42% | 9,711 |
| DoS | 96.11% | 76.57% | 85.23% | 7,460 |
| Probe | 86.44% | 53.52% | 66.11% | 2,752 |
| U2R | 54.55% | 8.96% | 15.38% | 67 |
| R2L | 95.34% | 7.20% | 13.40% | 2,554 |

The validation Macro F1 (98.26%) is materially higher than independent KDDTest+ Macro F1 (51.51%). U2R and R2L recall are especially low. Aggregate accuracy therefore does not describe performance across all attack classes. The model must not be the sole basis for security decisions or automatic traffic blocking.

## Interpretation of confusion patterns

The supplied KDDTest+ confusion matrix shows substantial R2L-to-Normal confusion (2,357 records) and DoS-to-Normal confusion (1,719 records). These missed detections reinforce the low recall results and should be discussed in the capstone presentation. The reported one-versus-rest false-positive-rate chart also shows a high Normal-class FPR; use the measured values from `artifacts/evaluation.json`, not approximations copied from a chart.

## Hosted prototype evidence

**Application:** https://group19-network-intrusion-detection.streamlit.app/  
**Repository:** https://github.com/adugnaNecho/Group19-network-intrusion-detection

The supplied screenshot shows a sample record uploaded to the interface and a DoS prediction with displayed maximum class probability 1.00 and severity High. This demonstrates the interface interaction for that row only; it does not prove that the label is correct or that the score is calibrated.

## Software testing

The final dashboard source package reports 29 automated tests passing. Software tests validate code paths and data handling; they do not establish classification accuracy or operational security effectiveness.

## Deployment hotfix status

The FPR chart data-schema/fallback correction was committed as source commit `8941226`. A prior Streamlit Cloud screenshot showed an unhandled ValueError at Plotly Express `px.bar()`. The group must confirm the hosted app has rebuilt from commit `8941226` and that the Analytics Dashboard displays the FPR chart or its fallback table without crashing.

## Limitations and future work

- NSL-KDD is a historical benchmark and does not represent all current enterprise traffic.
- Recall is low for U2R (8.96%) and R2L (7.20%); missed attacks remain a significant limitation.
- The public application classifies uploaded connection records. It does not capture live packets, block traffic, or provide production-grade monitoring.
- Displayed maximum class probability is not calibrated confidence unless a separate calibration evaluation is performed.
- SMOTENC-generated minority examples are used only during fitting; the independent KDDTest+ set remains untouched.

Next experiments should examine false negatives/confusion pairs, improve rare-class treatment using training-only cross-validation, assess class-sensitive objectives and probability calibration, and evaluate newer authorized datasets with verified labels. Keep a separate final test set untouched during model selection.
