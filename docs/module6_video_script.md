# Module 6 Capstone Video - 8 to 9 Minute Script

**Target duration:** 8:30 (maximum allowed: 10 minutes). Record a real screen demonstration after the model artifact is available and the application has been run successfully. Do not show an invented prediction.

| Time | Segment | What to show / say |
|---|---|---|
| 0:00-0:50 | Problem and solution | Introduce Group 19's project: a five-class ML classifier for NSL-KDD connection records. Explain the classes: Normal, DoS, Probe, U2R and R2L. Emphasize that this is benchmark-record classification, not a live packet capture system. |
| 0:50-2:10 | Dataset and processing | Show the notebook/repository. Explain 125,973 KDDTrain+ rows and 22,544 KDDTest+ rows, 41 features, label grouping, stratified validation split and held-out final test. Explain numeric scaling, categorical one-hot encoding, and leakage-safe SMOTENC within the training pipeline. |
| 2:10-3:30 | Model and experiments | Explain the Decision Tree and Random Forest baselines, XGBoost comparison, and selected Random Forest + SMOTENC pipeline. Mention 3-fold GridSearchCV, Macro-F1 objective, random seed 42 and selected hyperparameters (250 trees, max depth 20, min split 5). Show MLflow tracking code/results only if the run can be opened and verified. |
| 3:30-5:00 | Prototype demonstration | Start the Streamlit app. Download the included example CSV, upload it and click Predict. Show the actual class, confidence, severity and per-class probabilities; export the prediction CSV. State that the sample row is illustrative. If the artifact or app is not available, show the repository and clearly explain what remains to run; do not fabricate output. |
| 5:00-6:15 | Evaluation evidence | Show the validation and official KDDTest+ metrics. Report 99.89% validation accuracy / 0.9825 Macro-F1 versus 74.63% test accuracy / 0.5155 Macro-F1. Point out that all five proposal thresholds fail on KDDTest+ and that R2L/U2R recall is 0.06/0.10. |
| 6:15-7:25 | Deployment approach | Explain GitHub source control, Streamlit for the CSV UI and optional FastAPI `/predict` endpoint. Explain that a public repository alone does not host the model: the trusted model artifact must be released and the app separately deployed. Mention Docker as a reproducible packaging option. |
| 7:25-8:20 | Monitoring, security and maintenance | Cover latency/error monitoring, feature drift, verified labels, review-before-retraining, model versioning/checksums, analyst review, privacy and fallback IDS as future operational proposals, not implemented features. |
| 8:20-8:50 | Reflection and close | Summarize lessons about generalization, minority classes, test-set discipline and reproducibility. State limitations and next steps: improve R2L/U2R detection, assess drift, test current data and validate in a controlled pilot. |

## Recording checklist

- Record the actual app, not a slide claiming it is live when it is not.
- Keep the video at or below 10 minutes and 250 MB.
- Ensure the browser address bar is visible when showing public URLs.
- Do not show tokens, Kaggle credentials, private telemetry or personal data.
- Speak all five group members' contributions if this is a group presentation; each member should briefly explain their own work.
- Mention the dataset/synthetic-data statement and the independent-test generalization gap.
