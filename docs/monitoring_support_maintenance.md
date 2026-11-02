# Monitoring, Support and Maintenance Plan

**Status:** Proposed plan for a future controlled pilot. The current prototype does not implement continuous monitoring, live packet capture, automatic blocking, shadow deployment or a production on-call process.

## 1. Performance and service monitoring

For an approved pilot, record request volume, prediction latency (median and p95/p99), error rate, CPU/memory use, artifact version and prediction-class distribution. Establish baselines on actual deployment hardware and workload. Alert on sustained service failures, resource exhaustion and material latency regressions. The notebook's batch inference timing is environment-specific and is not an SLA.

Once analyst-confirmed labels are available, calculate accuracy, per-class precision/recall/F1, confusion matrices and false-positive rates on rolling labelled samples. Macro metrics and rare-class recall must be reported; overall accuracy alone can hide missed attacks. Current KDDTest+ recall is 8.96% for U2R and 7.20% for R2L, so analyst oversight is essential.

## 2. Data and concept drift

Compare incoming feature distributions against a documented training baseline. PSI and a two-sample KS test may be used as screening signals for numerical features, with thresholds calibrated against baseline variability. Monitor unseen category rates for `protocol_type`, `service` and `flag`, invalid/missing fields, and predicted-class distribution. Predicted labels are not ground truth; use verified analyst labels to evaluate concept drift and model quality. Do not retrain automatically solely because predicted class proportions change.

A pilot may begin review when PSI exceeds 0.2 for a key feature, an appropriately corrected drift test signals a sustained difference, or verified rolling Macro F1 falls below 0.80. These are proposed review triggers, not validated operational thresholds. Confirm the signal and investigate before retraining.

## 3. Retraining and release management

Collect only authorized, minimized and access-controlled telemetry. Have qualified analysts label representative samples, document label quality, and version the dataset and feature schema. Retrain on a planned cadence only when reviewed data justify it or when drift/degradation is confirmed. Use time-aware or network-aware evaluation where possible, keep validation data separate, and preserve an independent final test set untouched during model selection.

Record code revision, dependency versions, data version, random seed, hyperparameters, metrics, model checksum and reviewer approval. Evaluate candidate models offline, then in shadow mode on mirrored traffic without enforcement actions before any controlled rollout. Keep a previous trusted artifact for rollback.

## 4. Error handling and fallback

Reject malformed requests with clear client errors; log sanitized diagnostic details for server errors; never expose stack traces, secrets or internal paths to clients. Add health checks, timeouts, request-size limits and rate limiting before wider deployment. A model-load failure must stop prediction rather than silently returning a mock label.

A signature-based IDS such as Snort or Suricata could provide an independent detection layer in a future operational design, but this fallback is not configured in the current prototype. The prototype does not block or modify traffic.

## 5. Security, privacy and responsible use

Use only authorized telemetry, minimize retained fields, restrict access, define retention/deletion policies, and encrypt data in transit and at rest. Do not commit credentials, private captures or personally identifying information. Pin and review dependencies; verify artifact hashes; load joblib/pickle files only from trusted releases because deserialization can execute code. A SHA-256 sidecar can detect accidental corruption but is not a publisher signature.

Test performance across network segments, device types and attack categories. Treat low-confidence or high-impact predictions as requiring analyst review. The current dataset and model do not establish fairness, robustness, calibration or suitability for automatic enforcement.

## 6. Support and maintenance

Maintain issue templates for defects, data-quality problems, false positives/negatives, security reports and feature requests. Each incident should record time, software/model version, sanitized input characteristics, expected/actual behavior, severity, owner and resolution. Add reproducible regression tests before merging fixes. Review dependency updates in staging, rebuild the model if serialization compatibility changes, update the README/changelog, and retain a rollback option.

## 7. Proposed ownership

Assign named owners for data/model stewardship, application operations, security/privacy review, and analyst feedback before a pilot. The Module 5 notebook lists five members but does not assign work-package roles; complete `docs/team_contributions.md` with actual responsibilities before submission.
