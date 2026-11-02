"""Streamlit interface for single- and batch-record NIDS prediction."""
from pathlib import Path

import pandas as pd
import streamlit as st

from nids_core import DEFAULT_MODEL_PATH, FEATURE_COLUMNS, load_model, predict_records

st.set_page_config(page_title="Group 19 | Network Intrusion Detection", page_icon="🛡️", layout="wide")
st.title("Network Intrusion Detection System")
st.caption("Group 19 · NSL-KDD benchmark · Five-class Random Forest + SMOTENC prototype")
st.warning(
    "Research prototype only. It classifies NSL-KDD-style connection records; it does not capture live packets, "
    "block traffic, or provide production-grade security monitoring."
)

@st.cache_resource(show_spinner="Loading the trained model...")
def get_model():
    return load_model(DEFAULT_MODEL_PATH)

model = None
try:
    model = get_model()
except FileNotFoundError as exc:
    st.error("The trained model artifact is not present in this checkout.")
    st.code("python train_model.py", language="bash")
    st.caption(str(exc))

with st.expander("About the model and its limitations", expanded=False):
    st.markdown(
        "The model uses 41 connection-level features and maps detailed NSL-KDD attack labels to "
        "**Normal, DoS, Probe, U2R, and R2L**. In the uploaded notebook's recorded KDDTest+ evaluation, "
        "accuracy was **74.63%** and Macro-F1 was **0.5155**. R2L and U2R recall were **0.06** and **0.10**. "
        "Treat predictions as triage hints, not definitive incident decisions."
    )

st.subheader("1. Provide input records")
st.write("Upload a CSV containing the 41 NSL-KDD feature columns. The supplied sample file can be used to verify the interface.")
sample_path = Path("examples/sample_input.csv")
if sample_path.is_file():
    st.download_button(
        "Download 41-feature sample CSV",
        data=sample_path.read_bytes(),
        file_name="nids_sample_input.csv",
        mime="text/csv",
    )
upload = st.file_uploader("Upload CSV", type=["csv"])

if upload is not None:
    try:
        input_df = pd.read_csv(upload)
        st.write(f"Uploaded {len(input_df):,} record(s).")
        st.dataframe(input_df.head(5), use_container_width=True)
        if model is not None and st.button("Predict intrusion class", type="primary"):
            results = predict_records(model, input_df)
            st.subheader("2. Prediction results")
            st.dataframe(results, use_container_width=True)
            st.download_button(
                "Download predictions CSV",
                data=results.to_csv(index=False).encode("utf-8"),
                file_name="nids_predictions.csv",
                mime="text/csv",
            )
    except Exception as exc:
        st.error(f"Input could not be processed: {exc}")
else:
    st.info("No CSV uploaded yet. Download the sample above, or prepare a CSV with all 41 input features.")

with st.expander("Feature schema"):
    st.code(", ".join(FEATURE_COLUMNS), language="text")

st.divider()
st.caption("Dataset: NSL-KDD benchmark. No live network traffic is captured or transmitted by this application.")
