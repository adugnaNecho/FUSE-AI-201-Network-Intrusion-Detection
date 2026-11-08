"""Streamlit interface and analytics dashboard for Group 19's NSL-KDD NIDS."""
from pathlib import Path
import hashlib
import io
import os

import pandas as pd
import plotly.express as px
import streamlit as st

from nids_core import CLASS_NAMES, DEFAULT_MODEL_PATH, FEATURE_COLUMNS, load_model, predict_records
from nids_dashboard import (
    class_metrics_frame,
    confidence_frame,
    confusion_matrix_frame,
    fpr_frame,
    load_evaluation,
    METRIC_LABELS,
    metrics_comparison_frame,
    normal_vs_attack_profile,
    prediction_distribution,
    severity_distribution,
    traffic_profile,
)
from telemetry_client import TelemetryClientError, fetch_live_stats, resolve_setting

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / DEFAULT_MODEL_PATH
EVALUATION_PATH = BASE_DIR / "artifacts" / "evaluation.json"
SAMPLE_PATH = BASE_DIR / "examples" / "sample_input.csv"

st.set_page_config(
    page_title="Group 19 | Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_model():
    return load_model(MODEL_PATH)


@st.cache_resource(show_spinner="Loading the trained Random Forest + SMOTENC model...")
def cached_model():
    return get_model()


def confusion_matrix_style(frame: pd.DataFrame):
    """Apply a blue heatmap style without adding a matplotlib dependency."""
    maximum = max(int(frame.to_numpy().max()), 1)
    styles = pd.DataFrame("", index=frame.index, columns=frame.columns)
    for row_index in range(frame.shape[0]):
        for column_index in range(frame.shape[1]):
            intensity = float(frame.iat[row_index, column_index]) / maximum
            alpha = 0.08 + 0.68 * intensity
            styles.iat[row_index, column_index] = (
                f"background-color: rgba(35, 120, 190, {alpha:.2f});"
            )
    return frame.style.apply(lambda _: styles, axis=None)


def render_metric_cards(evaluation: dict, split_key: str, label: str):
    metrics = evaluation.get(split_key, {})
    columns = st.columns(4)
    for column, key in zip(columns, ("accuracy", "macro_precision", "macro_recall", "macro_f1")):
        value = metrics.get(key)
        if isinstance(value, (int, float)):
            column.metric(
                METRIC_CARD_LABELS[key],
                f"{float(value) * 100:.2f}%",
                help=f"{label} — calculated on the {metrics.get('records', 'reported')} records in this split.",
            )
        else:
            column.metric(METRIC_CARD_LABELS[key], "Not available")


METRIC_CARD_LABELS = {
    "accuracy": "Accuracy",
    "macro_precision": "Macro precision",
    "macro_recall": "Macro recall",
    "macro_f1": "Macro F1",
}


def render_dashboard(evaluation: dict, evaluation_source: str):
    st.header("NIDS Analytics Dashboard")
    st.caption("Benchmark evaluation and uploaded-record analytics. All charts are based on recorded evaluation artifacts or the current upload.")

    if evaluation_source == "evaluation_artifact":
        st.success("Loaded benchmark metrics, class-wise results and confusion matrix from artifacts/evaluation.json.")
    else:
        st.info(
            "Using the latest metrics transcribed from the successful training command. "
            "The full confusion matrix and per-class precision/F1 are not embedded in this fallback snapshot. "
            "The dashboard will display them automatically when artifacts/evaluation.json is present."
        )

    st.subheader("Model performance — independent KDDTest+ set")
    render_metric_cards(evaluation, "official_test", "Independent KDDTest+ evaluation")

    test_metrics = evaluation.get("official_test", {})
    if test_metrics.get("records"):
        st.caption(f"Independent test records: {int(test_metrics['records']):,} · Dataset: NSL-KDD KDDTest+ · Model: Random Forest + SMOTENC")

    st.subheader("Validation versus independent-test performance")
    comparison = metrics_comparison_frame(evaluation)
    if not comparison.empty:
        comparison_figure = px.bar(
            comparison,
            x="Metric",
            y="Score",
            color="Dataset",
            barmode="group",
            text_auto=".1%",
            category_orders={
                "Metric": list(METRIC_LABELS.values()),
                "Dataset": ["KDDTest+", "Validation"],
            },
            labels={"Score": "Score", "Metric": "Evaluation metric", "Dataset": "Dataset"},
        )
        comparison_figure.update_yaxes(
            range=[0, 1],
            tickformat=".0%",
            title="Score",
        )
        comparison_figure.update_traces(textposition="outside", cliponaxis=False)
        comparison_figure.update_layout(
            barmode="group",
            yaxis_range=[0, 1],
            legend_title_text="Dataset",
            margin=dict(t=65, r=20, b=20, l=20),
        )
        st.plotly_chart(comparison_figure, width="stretch", config={"displaylogo": False})
        st.caption("Bars are grouped (not stacked). Each score is shown as a proportion on a 0–100% axis. The gap between validation and KDDTest+ scores is material; independent-test results are the more conservative generalization estimate.")
    else:
        st.warning("No validation/test comparison values were found in the evaluation evidence.")

    left, right = st.columns((1.1, 1))
    with left:
        st.subheader("Class-wise test metrics")
        class_frame = class_metrics_frame(evaluation, "official_test")
        if not class_frame.empty:
            percent_columns = [column for column in ("Precision", "Recall", "F1-score") if column in class_frame.columns]
            formatters = {column: "{:.2%}" for column in percent_columns}
            if "Support" in class_frame.columns:
                formatters["Support"] = "{:,.0f}"
            styled = class_frame.style.format(formatters)
            st.dataframe(styled, width="stretch")
            if "Recall" in class_frame.columns:
                st.markdown("**Recall by attack class**")
                recall_plot = class_frame[["Recall"]].reset_index()
                recall_figure = px.bar(
                    recall_plot,
                    x="Class",
                    y="Recall",
                    text="Recall",
                    category_orders={"Class": CLASS_NAMES},
                    labels={"Recall": "Recall", "Class": "Actual class"},
                )
                recall_figure.update_traces(texttemplate="%{y:.1%}", textposition="outside", cliponaxis=False)
                recall_figure.update_yaxes(range=[0, 1], tickformat=".0%", title="Recall (%)")
                recall_figure.update_layout(showlegend=False, margin=dict(t=35, r=15, b=25, l=15))
                st.plotly_chart(recall_figure, width="stretch", config={"displaylogo": False})
        else:
            st.info("No class-wise metrics are available in the selected evaluation artifact.")

    with right:
        st.subheader("Confusion matrix — KDDTest+")
        cm = confusion_matrix_frame(evaluation, "official_test")
        if cm is not None:
            st.caption("Rows = actual class · Columns = predicted class")
            st.dataframe(confusion_matrix_style(cm), width="stretch")
            st.download_button(
                "Download confusion matrix CSV",
                cm.to_csv(index=True).encode("utf-8"),
                file_name="group19_kddtest_confusion_matrix.csv",
                mime="text/csv",
            )
        else:
            st.info("The confusion matrix is not available in the fallback metric snapshot. Use the evaluation.json generated by train_model.py to display the measured 5 × 5 matrix. No matrix is invented here.")

    fpr = fpr_frame(evaluation, "official_test")
    if not fpr.empty:
        st.subheader("One-versus-rest false-positive rate by class")
        # fpr_frame returns an explicit two-column table. Do not reset its index:
        # doing so can produce a different column name for some serialized frames.
        try:
            fpr_figure = px.bar(
                fpr,
                x="Class",
                y="False positive rate",
                text="False positive rate",
                category_orders={"Class": CLASS_NAMES},
                labels={"False positive rate": "False positive rate", "Class": "Actual class"},
            )
            fpr_figure.update_traces(texttemplate="%{y:.1%}", textposition="outside", cliponaxis=False)
            fpr_figure.update_yaxes(tickformat=".1%", title="False positive rate (%)", rangemode="tozero")
            fpr_figure.update_layout(showlegend=False, margin=dict(t=35, r=15, b=25, l=15))
            st.plotly_chart(fpr_figure, width="stretch", config={"displaylogo": False})
        except (ValueError, KeyError, TypeError) as exc:
            # An optional chart must not take down the entire app. Keep the
            # measured values inspectable while surfacing a concise diagnostic.
            st.warning(f"The FPR chart could not be rendered ({type(exc).__name__}). The measured values are shown below.")
            st.dataframe(fpr, width="stretch")
    elif evaluation_source == "reported_run_snapshot":
        st.caption("Class-wise false-positive rates were not included in the reported console summary; no values are inferred.")

    st.divider()
    st.subheader("Current uploaded-record analytics")
    uploaded_records = st.session_state.get("nids_uploaded_records")
    uploaded_predictions = st.session_state.get("nids_uploaded_predictions")

    if uploaded_records is None or uploaded_predictions is None:
        st.info("Upload a 41-feature CSV in the Prediction tab and click 'Predict intrusion class'. The charts below will then summarize that upload.")
        return

    st.caption(f"Current upload: {len(uploaded_records):,} record(s). The traffic plots show record order, not time; NSL-KDD input features do not include timestamps.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Uploaded records", f"{len(uploaded_records):,}")
    c2.metric("Predicted attack records", f"{int((uploaded_predictions['predicted_class'] != 'Normal').sum()):,}")
    c3.metric("Predicted Normal records", f"{int((uploaded_predictions['predicted_class'] == 'Normal').sum()):,}")

    left, right = st.columns(2)
    with left:
        st.markdown("**Predicted class distribution**")
        class_counts = prediction_distribution(uploaded_predictions)
        st.bar_chart(class_counts, height=270)
    with right:
        st.markdown("**Predicted threat-severity distribution**")
        severity_counts = severity_distribution(uploaded_predictions)
        st.bar_chart(severity_counts, height=270)

    st.markdown("**Normal versus predicted-attack traffic profile**")
    grouped_profile = normal_vs_attack_profile(uploaded_records, uploaded_predictions, feature="src_bytes")
    if not grouped_profile.empty:
        st.line_chart(grouped_profile, height=270)
        st.caption("Groups are based on model predictions (Normal vs any predicted attack), not ground-truth labels. Values use log10(src_bytes + 1); the horizontal axis is record order, not time.")

    st.markdown("**Network traffic feature profile**")
    profile = traffic_profile(uploaded_records)
    if not profile.empty:
        st.line_chart(profile, height=300)
        st.caption("Byte features are displayed as log10(value + 1) to make skewed magnitudes readable. Count and service-count fields retain their recorded scale.")
    else:
        st.info("No supported byte/count fields were found for the uploaded-record traffic chart.")

    confidence = confidence_frame(uploaded_predictions)
    if not confidence.empty:
        st.markdown("**Maximum class probability per uploaded record**")
        st.line_chart(confidence, height=220)
        st.caption("These are model maximum class probabilities, not calibrated probabilities of real-world threat.")

    st.download_button(
        "Download current prediction results",
        data=uploaded_predictions.to_csv(index=False).encode("utf-8"),
        file_name="group19_nids_predictions.csv",
        mime="text/csv",
        key="dashboard_download_predictions",
    )



@st.fragment(run_every="10s")
def render_live_monitoring():
    """Show only timestamped prediction events received by the telemetry API."""
    st.header("Live network telemetry")
    st.caption("Authenticated producer-submitted predictions · API polling every 10 seconds · UTC timestamps")

    try:
        secret_store = st.secrets
    except Exception:
        secret_store = None
    api_url = resolve_setting("LIVE_STATS_API_URL", secret_store)
    api_token = resolve_setting("LIVE_STATS_API_TOKEN", secret_store)

    if not api_url or not api_token:
        st.info(
            "Live monitoring is not connected yet. Configure LIVE_STATS_API_URL and "
            "LIVE_STATS_API_TOKEN in Streamlit Community Cloud secrets, deploy the separate "
            "FastAPI telemetry service, and connect a trusted producer that emits all 41 model features."
        )
        st.markdown("Setup instructions: [docs/live_telemetry_setup.md](https://github.com/adugnaNecho/FUSE-AI-201-Network-Intrusion-Detection/blob/main/docs/live_telemetry_setup.md)")
        st.caption("This app does not capture packets. Uploaded CSV records and NSL-KDD benchmark results are not treated as live telemetry.")
        return

    try:
        stats = fetch_live_stats(api_url, api_token, window_hours=24, timeout=5.0)
    except TelemetryClientError as exc:
        st.error(str(exc))
        st.caption("Live data is unavailable. Benchmark and uploaded-file analytics remain separate and unchanged.")
        return

    if stats.get("status") == "live":
        st.success("The telemetry API has received producer-submitted predictions in the last 24 hours.")
    else:
        st.info("The telemetry API is reachable, but it has received no records in the last 24 hours.")

    st.caption("Data origin: authenticated external producer submissions. The API stores prediction summaries only; producer provenance is not independently verified.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Predictions received · 24h", f"{int(stats.get('total_events_window', 0)):,}")
    c2.metric("Predictions recorded · all time", f"{int(stats.get('total_events_all_time', 0)):,}")
    c3.metric("Active producer IDs · 24h", f"{int(stats.get('active_sources_window', 0)):,}")

    last_received = stats.get("last_received_at") or "No readings received"
    st.caption(f"Last reading received (UTC): {last_received} · API snapshot: {stats.get('generated_at', 'unknown')}")

    st.subheader("Live predicted-class distribution · last 24 hours")
    class_counts = stats.get("class_counts", {})
    class_frame = pd.DataFrame.from_dict(class_counts, orient="index", columns=["Predicted records"])
    class_frame = class_frame.reindex(CLASS_NAMES).fillna(0).astype(int)
    st.bar_chart(class_frame, height=280)

    st.subheader("Incoming prediction volume · last hour")
    timeline = pd.DataFrame(stats.get("timeline_5m_last_hour", []))
    if not timeline.empty and "timestamp" in timeline.columns:
        timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], utc=True, errors="coerce")
        timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp")
        for class_name in CLASS_NAMES:
            if class_name not in timeline:
                timeline[class_name] = 0
        st.line_chart(timeline[CLASS_NAMES], height=300)
        if stats.get("timeline_truncated"):
            st.caption("The timeline is based on a bounded sample of the latest 20,000 event records. Summary totals use database counts.")
    else:
        st.info("No recent event timeline is available yet.")

    st.warning(
        "These are model predictions, not confirmed attacks. The incoming stream has no independently verified "
        "ground-truth labels, so live accuracy, precision, recall, F1-score, and a confusion matrix are not calculated. "
        "Maximum class probability is not a calibrated incident probability."
    )


evaluation, evaluation_source = load_evaluation(EVALUATION_PATH)

st.title("Network Intrusion Detection System")
st.caption("Group 19 · FUSE AI-201 · NSL-KDD benchmark · Five-class Random Forest + SMOTENC prototype")
st.warning(
    "Research prototype only. It classifies NSL-KDD-style connection records; it does not capture live packets, "
    "block traffic, or provide production-grade security monitoring."
)

try:
    model = cached_model()
except FileNotFoundError as exc:
    model = None
    model_error = str(exc)
except Exception as exc:
    model = None
    model_error = f"The model could not be loaded: {exc}"

if model is not None:
    st.success("Trained model loaded and ready for CSV inference.")
else:
    st.error("The trained model artifact could not be loaded.")
    st.code("artifacts/group19_final_nids_random_forest_pipeline.joblib", language="text")
    st.caption(model_error)

prediction_tab, dashboard_tab, live_tab, about_tab = st.tabs(["CSV Prediction", "Benchmark & Upload Analytics", "Live Monitoring", "About & Limitations"])

with prediction_tab:
    st.header("1. Provide input records")
    st.write("Upload a CSV containing the 41 NSL-KDD feature columns. The supplied sample file can be used to verify the interface.")
    if SAMPLE_PATH.is_file():
        st.download_button(
            "Download 41-feature sample CSV",
            data=SAMPLE_PATH.read_bytes(),
            file_name="nids_sample_input.csv",
            mime="text/csv",
        )

    upload = st.file_uploader("Upload CSV", type=["csv"], key="nids_csv_upload")
    if upload is not None:
        try:
            raw = upload.getvalue()
            upload_signature = hashlib.sha256(raw).hexdigest()
            input_df = pd.read_csv(io.BytesIO(raw))
            if st.session_state.get("nids_upload_signature") != upload_signature:
                st.session_state["nids_upload_signature"] = upload_signature
                st.session_state["nids_uploaded_predictions"] = None
            st.session_state["nids_uploaded_records"] = input_df.copy()
            st.write(f"Uploaded {len(input_df):,} record(s).")
            st.dataframe(input_df.head(5), width="stretch")

            if model is not None and st.button("Predict intrusion class", type="primary"):
                with st.spinner("Classifying uploaded connection records..."):
                    results = predict_records(model, input_df)
                st.session_state["nids_uploaded_predictions"] = results
                st.success(f"Prediction completed for {len(results):,} record(s). Open the Analytics Dashboard tab for charts and summary metrics.")

            saved_results = st.session_state.get("nids_uploaded_predictions")
            if saved_results is not None and st.session_state.get("nids_upload_signature") == upload_signature:
                st.subheader("Prediction results")
                st.dataframe(saved_results, width="stretch")
                st.download_button(
                    "Download predictions CSV",
                    data=saved_results.to_csv(index=False).encode("utf-8"),
                    file_name="nids_predictions.csv",
                    mime="text/csv",
                    key="prediction_tab_download",
                )
            elif model is None:
                st.info("The model is unavailable, so predictions cannot be generated in this deployment.")
        except Exception as exc:
            st.error(f"Input could not be processed: {exc}")
    else:
        st.info("No CSV uploaded yet. Download the sample above, or prepare a CSV with all 41 input features.")

    with st.expander("Required 41-feature schema"):
        st.code(", ".join(FEATURE_COLUMNS), language="text")

with dashboard_tab:
    render_dashboard(evaluation, evaluation_source)

with live_tab:
    render_live_monitoring()

with about_tab:
    st.header("About the model and its limitations")
    st.markdown(
        "The model uses 41 connection-level features and maps detailed NSL-KDD attack labels to "
        "**Normal, DoS, Probe, U2R, and R2L**. It is a benchmark-based research prototype, not a live packet sensor."
    )
    st.subheader("Latest independent-test results")
    render_metric_cards(evaluation, "official_test", "Independent KDDTest+ evaluation")
    recall_frame = class_metrics_frame(evaluation, "official_test")
    if not recall_frame.empty:
        st.markdown("**Class-wise test metrics available from the evaluation artifact**")
        st.dataframe(recall_frame, width="stretch")
    st.warning(
        "The latest independent KDDTest+ Macro F1 was approximately 51.51%. Recall was particularly low for U2R "
        "(8.96%) and R2L (7.20%). A displayed maximum class probability is not necessarily calibrated. "
        "Treat predictions as triage hints, not definitive incident decisions."
    )
    st.markdown(
        "**Not implemented:** packet capture and the feature-extraction component that converts actual network flows "
        "into the model's exact 41-feature training schema. A separate authenticated telemetry API and compatible "
        "producer must be deployed before the Live Monitoring tab can display incoming readings. Automatic blocking, "
        "continuous drift monitoring, production alerting, and a guaranteed service level are not provided."
    )
    st.markdown(
        "**Data:** benchmark results come from public NSL-KDD KDDTrain+ / KDDTest+ files. Uploaded CSV analytics "
        "describe only the uploaded records. Live statistics, when configured, describe timestamped predictions received "
        "from an external producer; the API does not independently verify their source."
    )

st.divider()
st.caption("Group 19 · FUSE AI-201 · Public research prototype · Packet capture is external; live telemetry is displayed only when a compatible authenticated producer is connected.")
