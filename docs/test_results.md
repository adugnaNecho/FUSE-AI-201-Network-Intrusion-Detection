# Group 19 - Module 6 Test and Demonstration Evidence

**Project:** Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification  
**Group:** Group 19 | FUSE AI-201  
**Run date:** November 2-3, 2026 (local time, as reported by the group)

## 1. Model training and export

The group ran `python train_model.py` successfully. KaggleHub downloaded and extracted the public NSL-KDD dataset. The script reported successful export of:

- `artifacts/group19_final_nids_random_forest_pipeline.joblib` (reported size: approximately 8.6 MB)
- `artifacts/group19_nids_class_mapping.json`
- `artifacts/evaluation.json`
- `artifacts/model.sha256`

### Latest metrics reported by the training command

| Metric | Validation | Independent KDDTest+ |
|---|---:|---:|
| Accuracy | 99.8921% | 74.6185% |
| Macro precision | 97.1660% | 79.3470% |
| Macro recall | 99.4620% | 48.7068% |
| Macro F1 | 98.2600% | 51.5101% |

Independent-test recall by class: Normal 97.2814%, DoS 76.5684%, Probe 53.5247%, U2R 8.9552%, R2L 7.2044%.

These benchmark results show a material validation-to-test generalization gap, particularly for U2R and R2L. They are not evidence of live enterprise network performance.

## 2. Automated software tests

The group previously reported running the original suite with:

```bash
python -m pytest -q
```

Original local result reported by the group:

```text
10 passed, 1 warning in 0.84s
```

The warning was a non-fatal Starlette deprecation warning concerning use of `httpx` with `starlette.testclient`.

The analytics-dashboard update adds `tests/test_dashboard.py`. In the preparation environment, the expanded combined suite completed with:

```text
24 passed in 0.36s
```

The expanded tests cover feature schema/input validation, prediction-output formatting with a deterministic test double, API request/schema behavior, evaluation artifact loading, grouped metric-comparison data, canonical class ordering across metrics and confusion matrices, support-count integer handling, false-positive-rate ordering, class/severity distributions, uploaded-record traffic profiles, Normal-versus-predicted-attack grouping, and confidence summaries. The group should rerun the expanded suite in its Windows environment after copying the dashboard update. Software tests do not establish the model's predictive accuracy.

## 3. Hosted Streamlit smoke test

**Public application:** https://group19-network-intrusion-detection.streamlit.app/  
**Public source repository:** https://github.com/adugnaNecho/Group19-network-intrusion-detection

The group reports that the hosted application installed dependencies, accepted a CSV upload and generated prediction results. The supplied screenshot documents one uploaded record with the following displayed output:

- Predicted class: DoS
- Displayed confidence: 1.00
- Threat severity: High
- Per-class outputs: Normal 0, DoS 1, Probe 0, U2R 0, R2L 0

This confirms the input-to-output path for the displayed sample record. It is not evidence that this individual prediction is correct, that confidence is calibrated, or that the model generalizes to operational traffic. A multi-record test and a signed-out browser check should also be retained by the group before final submission.

## 4. Evidence files

- `assets/streamlit_prediction_demo.png` - group-provided screenshot of the hosted application and one-record prediction.
- `evaluation_and_limitations.md` - interpretation of evaluation results and limitations.
- `module6_video_script.md` - presentation plan for a screen-recorded demonstration.
