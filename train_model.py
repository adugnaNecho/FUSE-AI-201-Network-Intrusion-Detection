"""Reproduce the Group 19 Random Forest + SMOTENC NSL-KDD model.

By default, uses the selected hyperparameters recorded in the Module 5 notebook.
Pass --tune to repeat the 3-fold GridSearchCV search from the notebook.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from imblearn.over_sampling import SMOTENC
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline

from nids_core import (
    CATEGORICAL_FEATURES, CLASS_NAMES, FEATURE_COLUMNS, ID_TO_LABEL,
    LABEL_TO_ID,
)

RANDOM_STATE = 42
COLUMN_NAMES = FEATURE_COLUMNS + ["class", "difficulty_level"]

ATTACK_MAPPING = {
    "normal": "Normal",
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS",
    "udpstorm": "DoS", "processtable": "DoS", "mailbomb": "DoS", "worm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "satan": "Probe",
    "portsweep": "Probe", "mscan": "Probe", "saint": "Probe", "snmpguess": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "snmpgetattack": "R2L",
    "named": "R2L", "sendmail": "R2L", "xlock": "R2L", "xsnoop": "R2L",
    "httptunnel": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}


def find_dataset_files(data_dir: Path) -> tuple[Path, Path]:
    train_file, test_file = data_dir / "KDDTrain+.txt", data_dir / "KDDTest+.txt"
    if train_file.is_file() and test_file.is_file():
        return train_file, test_file

    try:
        import kagglehub
    except ImportError as exc:
        raise RuntimeError(
            "NSL-KDD files are not present in ./data and kagglehub is not installed. "
            "Install requirements or place KDDTrain+.txt and KDDTest+.txt in ./data."
        ) from exc

    try:
        downloaded = Path(kagglehub.dataset_download("hassan06/nslkdd"))
    except Exception as exc:
        raise RuntimeError(
            "Could not download the public NSL-KDD dataset through kagglehub. "
            "Check internet access, or manually place KDDTrain+.txt and KDDTest+.txt in ./data."
        ) from exc

    # KaggleHub may return a directory containing the files directly or nested.
    candidates = list(downloaded.rglob("KDDTrain+.txt"))
    if not candidates:
        raise FileNotFoundError(f"KDDTrain+.txt was not found under downloaded dataset path: {downloaded}")
    train_file = candidates[0]
    test_file = train_file.parent / "KDDTest+.txt"
    if not test_file.is_file():
        raise FileNotFoundError(f"KDDTest+.txt was not found beside {train_file}")
    return train_file, test_file


def load_data(data_dir: Path):
    train_file, test_file = find_dataset_files(data_dir)
    train = pd.read_csv(train_file, header=None, names=COLUMN_NAMES)
    test = pd.read_csv(test_file, header=None, names=COLUMN_NAMES)

    for frame, label in ((train, "KDDTrain+"), (test, "KDDTest+")):
        frame["target"] = frame["class"].astype(str).str.lower().map(ATTACK_MAPPING)
        unmapped = sorted(frame.loc[frame["target"].isna(), "class"].astype(str).unique())
        if unmapped:
            raise ValueError(f"Unmapped raw labels in {label}: {unmapped}")
        frame["target_id"] = frame["target"].map(LABEL_TO_ID).astype(int)
    return train, test


def build_pipeline(X_train: pd.DataFrame):
    numeric_features = [c for c in X_train.columns if c not in CATEGORICAL_FEATURES]
    categorical_indices = [X_train.columns.get_loc(c) for c in CATEGORICAL_FEATURES]
    try:
        encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:  # compatibility with older scikit-learn
        encoder = OneHotEncoder(handle_unknown="ignore", sparse=False)

    preprocessor = ColumnTransformer([
        ("num", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]), numeric_features),
        ("cat", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", encoder),
        ]), CATEGORICAL_FEATURES),
    ])

    pipeline = ImbPipeline([
        ("smotenc", SMOTENC(
            categorical_features=categorical_indices,
            random_state=RANDOM_STATE,
            k_neighbors=1,
        )),
        ("preprocess", preprocessor),
        ("model", RandomForestClassifier(
            n_estimators=250,
            max_depth=20,
            min_samples_split=5,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight=None,
        )),
    ])
    return pipeline


def calculate_fpr(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(CLASS_NAMES))))
    total = int(cm.sum())
    output = {}
    for i, label in enumerate(CLASS_NAMES):
        tp = int(cm[i, i])
        fn = int(cm[i, :].sum() - tp)
        fp = int(cm[:, i].sum() - tp)
        tn = total - tp - fn - fp
        output[label] = float(fp / (fp + tn)) if (fp + tn) else 0.0
    return output


def evaluate(model, X, y, split_name: str):
    start = time.perf_counter()
    predicted = model.predict(X)
    elapsed = time.perf_counter() - start
    metrics = {
        "split": split_name,
        "records": int(len(y)),
        "accuracy": float(accuracy_score(y, predicted)),
        "macro_precision": float(precision_score(y, predicted, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y, predicted, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y, predicted, average="macro", zero_division=0)),
        "per_class": classification_report(
            y, predicted, labels=list(range(len(CLASS_NAMES))),
            target_names=CLASS_NAMES, output_dict=True, zero_division=0,
        ),
        "false_positive_rate_ovr": calculate_fpr(y, predicted),
        "confusion_matrix": confusion_matrix(y, predicted, labels=list(range(len(CLASS_NAMES)))).tolist(),
        "inference_total_seconds": float(elapsed),
        "inference_ms_per_record": float(elapsed * 1000 / max(len(y), 1)),
    }
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train and evaluate the Group 19 NSL-KDD NIDS.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--tune", action="store_true", help="Repeat the notebook's 3-fold, 8-setting grid search.")
    parser.add_argument("--mlflow", action="store_true", help="Log this run to a local MLflow tracking store.")
    args = parser.parse_args()

    np.random.seed(RANDOM_STATE)
    train, test = load_data(args.data_dir)
    drop = ["class", "target", "target_id", "difficulty_level"]
    X_full = train.drop(columns=drop)
    y_full = train["target_id"].astype(int)
    X_test = test[FEATURE_COLUMNS]
    y_test = test["target_id"].astype(int)

    X_train, X_val, y_train, y_val = train_test_split(
        X_full, y_full, test_size=0.1765, stratify=y_full, random_state=RANDOM_STATE,
    )
    estimator = build_pipeline(X_train)
    selected_params = {
        "model__n_estimators": 250,
        "model__max_depth": 20,
        "model__min_samples_split": 5,
    }

    if args.tune:
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
        search = GridSearchCV(
            estimator,
            param_grid={
                "model__n_estimators": [150, 250],
                "model__max_depth": [None, 20],
                "model__min_samples_split": [2, 5],
            },
            scoring="f1_macro", cv=cv, n_jobs=-1, verbose=1, refit=True,
        )
        search.fit(X_train, y_train)
        model = search.best_estimator_
        selected_params = search.best_params_
        cv_macro_f1 = float(search.best_score_)
    else:
        model = estimator
        model.fit(X_train, y_train)
        cv_macro_f1 = None

    validation_metrics = evaluate(model, X_val, y_val, "validation")
    # KDDTest+ is evaluated only after the model configuration is fixed.
    test_metrics = evaluate(model, X_test, y_test, "official_test")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / "group19_final_nids_random_forest_pipeline.joblib"
    joblib.dump(model, model_path, compress=3)

    mapping = {
        "class_names": CLASS_NAMES,
        "label_to_id": LABEL_TO_ID,
        "id_to_label": {str(k): v for k, v in ID_TO_LABEL.items()},
        "threat_severity": {"Normal": "Low", "Probe": "Medium", "DoS": "High", "R2L": "High", "U2R": "Critical"},
        "feature_columns": FEATURE_COLUMNS,
    }
    (args.output_dir / "group19_nids_class_mapping.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")

    metadata = {
        "project": "Group 19 NSL-KDD multi-class NIDS",
        "model": "RandomForestClassifier with SMOTENC preprocessing pipeline",
        "selected_parameters": selected_params,
        "cv_macro_f1": cv_macro_f1,
        "random_state": RANDOM_STATE,
        "dataset": "NSL-KDD KDDTrain+ / KDDTest+",
        "training_records": int(len(X_train)),
        "validation_records": int(len(X_val)),
        "test_records": int(len(X_test)),
        "features": len(FEATURE_COLUMNS),
        "classes": CLASS_NAMES,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "scikit_learn_version": sklearn.__version__,
        "validation": validation_metrics,
        "official_test": test_metrics,
        "notes": [
            "SMOTENC creates synthetic minority samples inside the training pipeline only.",
            "KDDTest+ is held out from model fitting and hyperparameter selection.",
            "Benchmark results are not evidence of live enterprise network performance.",
        ],
    }
    (args.output_dir / "evaluation.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    try:
        import hashlib
        digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
        (args.output_dir / "model.sha256").write_text(f"{digest}  {model_path.name}\n", encoding="utf-8")
    except OSError:
        pass

    if args.mlflow:
        try:
            import mlflow
            import mlflow.sklearn
        except ImportError as exc:
            raise RuntimeError("Install mlflow before using --mlflow: pip install mlflow") from exc
        mlflow.set_experiment("Group19-NSL-KDD-NIDS")
        with mlflow.start_run(run_name="RandomForest-SMOTENC"):
            mlflow.log_params({k: str(v) for k, v in selected_params.items()})
            mlflow.log_param("sampler", "SMOTENC")
            mlflow.log_param("random_state", RANDOM_STATE)
            for prefix, values in (("val", validation_metrics), ("test", test_metrics)):
                for key in ("accuracy", "macro_precision", "macro_recall", "macro_f1", "inference_ms_per_record"):
                    mlflow.log_metric(f"{prefix}_{key}", float(values[key]))
            mlflow.log_artifact(str(args.output_dir / "evaluation.json"))
            mlflow.sklearn.log_model(model, artifact_path="nids_pipeline")

    print(json.dumps({
        "model_path": str(model_path),
        "validation": {k: validation_metrics[k] for k in ("accuracy", "macro_precision", "macro_recall", "macro_f1")},
        "official_test": {k: test_metrics[k] for k in ("accuracy", "macro_precision", "macro_recall", "macro_f1")},
        "test_class_recall": {k: v["recall"] for k, v in test_metrics["per_class"].items() if k in CLASS_NAMES},
    }, indent=2))
    print("Model export complete. Keep this artifact with the same dependency versions used for training.")


if __name__ == "__main__":
    main()
