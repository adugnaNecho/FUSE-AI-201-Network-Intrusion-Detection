# Group 19 - Module 6 Capstone Video Script

**Target duration:** 8 minutes 30 seconds (must remain under 10 minutes)  
**Maximum file size:** 250 MB  
**Public app:** https://group19-network-intrusion-detection.streamlit.app/  
**Public repository:** https://github.com/adugnaNecho/Group19-network-intrusion-detection

This is a suggested narration and demonstration sequence. Adapt it to what the group actually implemented and each member's true contribution. Do not invent results or claim production capabilities.

| Time | Segment | Suggested narration and screen action |
|---|---|---|
| 0:00–0:40 | Introduction and problem | “We are Group 19. Our project is Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification. We classify network connection records into Normal, DoS, Probe, U2R and R2L. Our deliverable is a research prototype for uploaded NSL-KDD-style records, not a live packet sensor or traffic-blocking system.” Show title and public app. |
| 0:40–1:40 | Dataset and problem framing | Explain public NSL-KDD KDDTrain+ and KDDTest+, 41 connection features, five-class label mapping and dataset limitations. State that the dataset is a public benchmark, not a current live enterprise traffic feed. |
| 1:40–2:40 | Model pipeline | Show the notebook or README. Explain numeric/categorical preprocessing, SMOTENC inside the training pipeline, Random Forest classifier and three-fold GridSearchCV. State that SMOTENC synthetic examples are used only during model fitting; validation and official KDDTest+ records are not oversampled. |
| 2:40–4:20 | Live app demonstration | Open the Streamlit app. Show the research-prototype disclaimer; download/sample CSV; upload all 41 required features; click Predict intrusion class; show predicted class, maximum class probability, threat severity, five class probabilities and result CSV download. The supplied one-record screenshot shows DoS, displayed probability 1.00, severity High; describe it as an illustrative interface example, not a verified attack. If a multi-record CSV is used, state its actual row count. |
| 4:20–5:40 | Analytics dashboard and evaluation | Show grouped validation/test bars, class metrics and confusion matrix. Report validation: 99.89% accuracy and 98.26% Macro F1. Report KDDTest+: 74.62% accuracy and 51.51% Macro F1. Show class recall: Normal 97.28%, DoS 76.57%, Probe 53.52%, U2R 8.96%, R2L 7.20%. Emphasize the generalization gap and rare-class weakness. |
| 5:40–6:30 | Testing and deployment | Show GitHub repository and Streamlit URL. Explain GitHub version control/artifact storage and Streamlit Community Cloud hosting. State that the final source package QA reported 29 automated tests passing. Distinguish software tests from model accuracy. Mention FastAPI and Docker are optional included paths, not separate production services. |
| 6:30–7:40 | Monitoring and maintenance | Explain the proposed future plan: latency/error/resource monitoring, verified labels, drift screening, reviewed retraining, artifact/version/checksum tracking, analyst oversight, privacy safeguards, staged/shadow evaluation and rollback. Clearly say these continuous controls are proposed and not active services in the prototype. |
| 7:40–8:30 | Reflection and close | Summarize achievements, challenges, lessons and future work: improve U2R/R2L recall, evaluate newer authorized datasets, assess calibration, obtain verified labels, and conduct a controlled pilot with human review. End by stating that the work is a functional prototype with documented limitations, not a production IDS. |

## Suggested closing statement

“Group 19 has progressed from model development to a publicly accessible research prototype. The application demonstrates CSV-based five-class prediction and an analytics dashboard. The independent KDDTest+ results show that generalization, particularly for U2R and R2L, needs improvement. We therefore present this work as a functional prototype with a realistic monitoring and maintenance plan, not as a production intrusion prevention system.”

## Recording checklist

- Keep the recording under 10 minutes and under 250 MB.
- Show the actual public app, input and prediction output.
- Report validation and independent-test metrics separately.
- Discuss U2R/R2L recall and do not claim production readiness.
- Identify public benchmark data, constructed sample input and SMOTENC synthetic training examples.
- Confirm the Streamlit Cloud hotfix deployment before recording the FPR chart section (source commit `8941226`; hosted rebuild confirmation remains a group check).
- Each member should explain their actual contribution; update `docs/team_contributions.md` before recording.
- Hide credentials, private network data and unrelated personal information.
