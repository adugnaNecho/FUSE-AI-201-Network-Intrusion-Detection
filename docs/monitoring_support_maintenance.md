# Monitoring, Support and Maintenance Plan

**Status:** proposed plan for a future pilot. No continuous monitoring service, live packet sensor, automatic blocking, shadow deployment or production on-call process is implemented by this repository.

## 1. Performance and service monitoring

For an approved pilot, record request volume, prediction latency (median and p95/p99), error rate, CPU/memory use, artifact version, and prediction-class distribution. Establish baselines under the actual deployment hardware and expected traffic. The Module 5 notebook's 0.119 ms/record batch average is environment-specific and must not be adopted as an SLA. Alert on sustained service failures, resource exhaustion and material latency regressions.

Once analyst-confirmed labels are available, calculate accuracy, per-class precision/recall/F1, confusion matrices and false-positive rates on a rolling labelled sample. Macro metrics and rare-class recall must be reported; overall accuracy alone can hide missed attacks. The present KDDTest+ results, especially R2L recall 0.06 and U2R recall 0.10, make analyst oversight essential.

## 2. Data and concept drift

Compare incoming feature distributions against a documented training baseline. PSI and a two-sample KS test may be used as screening signals for numerical features, with thresholds calibrated on baseline variability. Monitor new/unseen category rates for `protocol_type`, `service` and `flag`, missing/invalid fields, and prediction-class distribution. Predicted labels are not ground truth; use verified analyst labels to evaluate concept drift and model quality. Do not auto-retrain solely because the predicted class proportions change.

A pilot may begin review when PSI exceeds 0.2 for a key feature, when an appropriately corrected drift test signals a sustained difference, or when verified rolling Macro-F1 drops below 0.80. These are proposed review triggers, not validated thresholds. Confirm the signal, investigate changes in topology and traffic, and approve a retraining plan before training.

## 3. Retraining and release management

Collect only authorized, minimized and access-controlled telemetry. Have qualified analysts label a representative sample, document label quality, and version the dataset and feature schema. Retrain on a planned cadence (for example, monthly during a pilot) only when enough reviewed data justify it, or after confirmed drift/degradation. Use a time-aware or network-aware evaluation where possible to reduce leakage from repeated/near-duplicate records. Keep validation data separate and maintain a final test set that is not used for model selection.

Record code revision, dependency versions, data version, random seed, hyperparameters, metrics, model checksum and reviewer approval. Evaluate a candidate offline, then run it in shadow mode on mirrored traffic without enforcement actions before any controlled rollout. Keep the previous trusted artifact for rollback.

## 4. Error handling and fallback

Reject malformed requests with a clear 4xx response; log sanitized diagnostic details for server errors; never return stack traces, secrets or internal file paths to clients. Add health checks, timeouts, request-size limits and rate limiting before public deployment. A model-load failure must fail closed for prediction rather than silently returning a mock label.

For an operational network, integrate with existing controls only after a separate security review. A signature-based IDS such as Snort or Suricata could provide an independent detection layer, but a fallback is a future architecture proposal and is not configured here. The prototype itself must not block or modify traffic.

## 5. Security, privacy and responsible AI

Use only authorized telemetry, minimize retained fields, restrict access, define retention/deletion policies and encrypt data in transit and at rest. Do not commit credentials, private captures or personally identifying information. Pin and regularly review dependencies, scan images/packages, restrict API exposure, and verify model artifact hashes. A SHA-256 sidecar detects accidental corruption but is not a signature against a malicious publisher. Only load model files from a trusted, reviewed release because joblib/pickle deserialization can execute code.

Test performance across network segments, device types and attack categories. Treat low-confidence or high-impact predictions as requiring analyst review, and do not interpret confidence as a calibrated probability unless calibration has been evaluated. The present dataset and model do not establish fairness, robustness or suitability for automated enforcement.

## 6. Support and maintenance

Maintain issue templates for defects, data-quality problems, false positives/negatives, security reports and feature requests. Each incident should record timestamp, software/model version, sanitized input characteristics, expected and actual behavior, severity, owner and resolution. Use reproducible test cases and regression tests before merging fixes. Review dependency updates in a staging environment, rebuild the model when serialization compatibility changes, update the README/changelog, and retain a rollback option.

## 7. Proposed ownership

Before a pilot, assign named owners for model/data stewardship, application/API operations, security/privacy review and analyst feedback. Group 19's supplied notebook lists five members but does not document role assignments; the team contribution sheet should be completed by the members before submission.
