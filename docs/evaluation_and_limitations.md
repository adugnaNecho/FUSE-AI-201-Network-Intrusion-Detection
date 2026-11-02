# Evaluation Evidence and Limitations

## Dataset and split protocol

The supplied Module 5 notebook loads the public NSL-KDD `KDDTrain+` and `KDDTest+` files. The recorded shapes are 125,973 training records and 22,544 independent test records, each with 41 input features plus the class label and difficulty metadata. Raw labels are grouped into five classes: Normal, DoS, Probe, U2R and R2L.

A stratified validation split is created from `KDDTrain+` with `test_size=0.1765` and `random_state=42`: 103,738 training records and 22,235 validation records. The official `KDDTest+` set remains outside fitting and tuning and is used for final evaluation. Numeric imputation/scaling and categorical imputation/one-hot encoding are inside the model pipeline. SMOTENC is placed inside an imbalanced-learn pipeline so resampling is fitted only on the active training partition/fold.

## Reported results from the uploaded notebook

| Metric | Held-out validation (KDDTrain+ split) | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.8876% | 74.6274% |
| Macro precision | 97.1483% | 80.0803% |
| Macro recall | 99.4603% | 48.8729% |
| Macro F1 | 98.2503% | 51.5480% |

The three-fold grid search recorded best cross-validation Macro-F1 of 0.9019 and selected `n_estimators=250`, `max_depth=20`, and `min_samples_split=5`. The independent-test class recalls were: Normal 0.97, DoS 0.77, Probe 0.54, U2R 0.10 and R2L 0.06. The one-versus-rest false-positive rate was 0.408166 for the Normal class, the largest among the classes. The notebook's five proposal thresholds (accuracy >= 0.90, Macro-F1 >= 0.85, macro precision >= 0.85, macro recall >= 0.85 and maximum class FPR < 0.05) were all marked **Fail** on the official test set.

The notebook's batch timing measurement covered 1,000 test records and recorded 0.1190 seconds total, or 0.1190 ms per record on that specific Colab runtime. This is a historical benchmark measurement, not a deployment guarantee. The notebook also recorded one-versus-rest ROC-AUC values between 0.9267 and 0.9723; these do not override the poor R2L/U2R recall or the generalization gap.

## Interpretation

The high hold-out validation score does not transfer to the independent KDDTest+ set. R2L and U2R are particularly difficult for this model, and many R2L records are predicted as Normal. A production system must not rely on the prototype as a sole detection or blocking mechanism. Treat each prediction as a research/triage indication requiring analyst review.

Possible explanations include distribution shift between KDDTrain+ and KDDTest+, different attack signatures in the test benchmark, minority-class sample scarcity and overlapping feature patterns. These are hypotheses for follow-up investigation, not causes proven by the present experiment.

## What has and has not been tested

- **Reported in the notebook:** benchmark split metrics, class-wise report, confusion matrix, per-class FPR, ROC-AUC, feature importance, a batch inference timing, model export/reload consistency.
- **Added in this repository:** deterministic unit tests for the 41-feature input schema, validation errors, prediction-output formatting using a test double, and API schema/empty-request behavior. These tests do not evaluate the learned classifier.
- **Not verified in this packaging environment:** rebuilding the actual model artifact, running the complete training script, loading the real artifact in Streamlit/FastAPI, or deploying a public web app. The supplied uploads did not contain the `.joblib` model file, and package/data downloads were unavailable in this runtime.

## Next experiments

1. Re-run the training pipeline in a network-enabled, resource-appropriate environment and verify metrics against the saved notebook outputs.
2. Investigate KDDTrain+/KDDTest+ label and feature distributions, especially R2L/U2R errors and false-Normal predictions.
3. Compare class-sensitive objectives, carefully controlled resampling, calibrated probabilities and anomaly-detection approaches using training-only cross-validation.
4. Keep the official test set untouched until a final, pre-registered evaluation. Report new results separately; do not overwrite historic results without a reproducible run record.
