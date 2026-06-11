import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelBinarizer, OneHotEncoder, RobustScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from app.core.config import BASE_DIR, get_settings

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None


DEFAULT_DATASET = BASE_DIR / "data" / "network_traffic_sample.csv"

CANONICAL_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "protocol_type",
    "service",
    "flag",
    "label",
]

DATASET_PROFILES = {
    "custom": "User supplied CSV dataset",
    "sample": "Built-in sample dataset",
    "nsl-kdd": "NSL-KDD style feature mapping",
    "cicids2017": "CICIDS2017 style feature mapping",
    "unsw-nb15": "UNSW-NB15 style feature mapping",
}

ATTACK_EXPLANATIONS = {
    "normal": "Legitimate traffic pattern without strong malicious indicators.",
    "benign": "Legitimate or expected network behavior.",
    "dos": "Denial-of-service behavior with repeated connection pressure or traffic flooding.",
    "probe": "Reconnaissance activity such as scanning hosts, ports, or services.",
    "r2l": "Remote-to-local attack attempt using credentials, payload delivery, or vulnerable services.",
    "u2r": "Privilege-escalation behavior where limited access tries to become administrator or root.",
}


@dataclass
class DatasetBundle:
    frame: pd.DataFrame
    profile_used: str
    dataset_path: str


def bootstrap_sample_dataset(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        "duration,src_bytes,dst_bytes,count,srv_count,same_srv_rate,diff_srv_rate,dst_host_count,dst_host_srv_count,protocol_type,service,flag,label",
        "0,181,5450,2,2,1.0,0.0,9,9,tcp,http,SF,normal",
        "0,239,486,5,5,1.0,0.0,19,19,tcp,http,SF,normal",
        "0,0,0,245,12,0.05,0.87,255,17,tcp,smtp,S0,dos",
        "0,0,0,232,4,0.02,0.94,255,8,tcp,ftp,S0,dos",
        "2,12983,0,3,1,0.33,0.66,45,5,udp,domain_u,SF,probe",
        "1,20,0,6,3,0.5,0.5,78,18,udp,private,REJ,probe",
        "10,500,120,1,1,1.0,0.0,3,3,tcp,telnet,SF,r2l",
        "8,1200,90,2,1,0.5,0.5,6,2,tcp,ftp_data,SF,r2l",
        "12,4000,200,1,1,1.0,0.0,2,2,tcp,ssh,SF,u2r",
        "7,3000,180,1,1,1.0,0.0,2,2,tcp,exec,SF,u2r",
        "0,340,1520,4,4,1.0,0.0,12,12,tcp,http,SF,normal",
        "0,0,0,210,14,0.06,0.8,255,31,tcp,http,S0,dos",
        "1,220,15,7,2,0.28,0.71,88,14,udp,private,RSTR,probe",
        "6,1100,70,2,1,0.5,0.5,5,1,tcp,ftp,SF,r2l",
        "11,3900,260,1,1,1.0,0.0,2,2,tcp,shell,SF,u2r",
    ]
    path.write_text("\n".join(rows), encoding="utf-8")


def _normalize_profile(profile: str | None) -> str:
    if not profile:
        return "custom"
    normalized = profile.strip().lower()
    return normalized if normalized in DATASET_PROFILES else "custom"


def _bootstrap_realistic_profile(profile: str, path: Path) -> None:
    bootstrap_sample_dataset(path)
    frame = pd.read_csv(path)
    if profile == "cicids2017":
        frame["service"] = frame["service"].replace({"http": "web", "ftp": "file-transfer"})
    if profile == "unsw-nb15":
        frame["flag"] = frame["flag"].replace({"SF": "CON", "S0": "INT"})
    path.write_text(frame.to_csv(index=False), encoding="utf-8")


def _load_dataset(csv_path: str, profile: str) -> DatasetBundle:
    data_path = Path(csv_path)
    if not data_path.is_absolute():
        data_path = BASE_DIR / data_path
    if not data_path.exists():
        if data_path == DEFAULT_DATASET:
            bootstrap_sample_dataset(data_path)
        elif profile in {"nsl-kdd", "cicids2017", "unsw-nb15"}:
            _bootstrap_realistic_profile(profile, data_path)
        else:
            raise FileNotFoundError(f"Dataset not found: {data_path}")

    frame = pd.read_csv(data_path)
    return DatasetBundle(frame=frame, profile_used=profile, dataset_path=str(data_path))


def _resolve_column(frame: pd.DataFrame, candidates: list[str]) -> str | None:
    lowered_map = {col.lower(): col for col in frame.columns}
    for candidate in candidates:
        if candidate.lower() in lowered_map:
            return lowered_map[candidate.lower()]
    return None


def _coerce_label(value: Any) -> str:
    lowered = str(value).strip().lower()
    mapping = {
        "back": "dos",
        "neptune": "dos",
        "smurf": "dos",
        "satan": "probe",
        "ipsweep": "probe",
        "portsweep": "probe",
        "guess_passwd": "r2l",
        "warezclient": "r2l",
        "buffer_overflow": "u2r",
        "rootkit": "u2r",
        "normal": "normal",
        "benign": "normal",
    }
    return mapping.get(lowered, lowered)


def _prepare_profile_frame(frame: pd.DataFrame, profile: str, target_column: str) -> pd.DataFrame:
    local = frame.copy()
    label_column = _resolve_column(local, [target_column, "label", "class", "attack_cat", "attack", "Label"])
    if label_column is None:
        raise ValueError(f"Target column '{target_column}' not found in dataset")

    if profile in {"custom", "sample"} and set(CANONICAL_COLUMNS).issubset(local.columns):
        local["label"] = local[label_column].map(_coerce_label)
        return local[CANONICAL_COLUMNS]

    mappings = {
        "duration": ["duration", "flow duration", "dur", "ct_flw_http_mthd"],
        "src_bytes": ["src_bytes", "tot fwd pkts", "sbytes", "total length of fwd packets"],
        "dst_bytes": ["dst_bytes", "tot bwd pkts", "dbytes", "total length of bwd packets"],
        "count": ["count", "flow packets/s", "ct_dst_src_ltm", "ct_srv_src"],
        "srv_count": ["srv_count", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm"],
        "same_srv_rate": ["same_srv_rate", "down/up ratio", "same_sport_rate", "ct_src_dport_ltm"],
        "diff_srv_rate": ["diff_srv_rate", "flow bytes/s", "dttl", "sload"],
        "dst_host_count": ["dst_host_count", "dst_host_srv_count", "dpkts", "dst_host_count"],
        "dst_host_srv_count": ["dst_host_srv_count", "spkts", "ct_dst_sport_ltm", "dst_host_srv_count"],
        "protocol_type": ["protocol_type", "protocol", "proto"],
        "service": ["service", "service", "protocol name"],
        "flag": ["flag", "state"],
    }

    canonical = {}
    for target_name, candidates in mappings.items():
        source = _resolve_column(local, candidates)
        if source is None:
            canonical[target_name] = 0 if target_name not in {"protocol_type", "service", "flag"} else "unknown"
        else:
            canonical[target_name] = local[source]

    prepared = pd.DataFrame(canonical)
    prepared["label"] = local[label_column].map(_coerce_label)
    return prepared[CANONICAL_COLUMNS]


def _engineer_features(frame: pd.DataFrame) -> pd.DataFrame:
    local = frame.copy()
    local["total_bytes"] = local["src_bytes"] + local["dst_bytes"]
    local["byte_ratio"] = np.where(local["dst_bytes"] > 0, local["src_bytes"] / (local["dst_bytes"] + 1), local["src_bytes"])
    local["connection_pressure"] = local["count"] + local["srv_count"] + local["dst_host_count"]
    local["service_diversity"] = local["diff_srv_rate"] - local["same_srv_rate"]
    local["host_service_balance"] = np.where(
        local["dst_host_count"] > 0,
        local["dst_host_srv_count"] / (local["dst_host_count"] + 1),
        0,
    )
    local["is_zero_payload"] = ((local["src_bytes"] + local["dst_bytes"]) == 0).astype(int)
    return local





def _build_preprocessor(x: pd.DataFrame) -> tuple[ColumnTransformer, list[str], list[str]]:
    categorical_columns = x.select_dtypes(include=["object"]).columns.tolist()
    numeric_columns = [col for col in x.columns if col not in categorical_columns]
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", RobustScaler()),
                    ]
                ),
                numeric_columns,
            ),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_columns,
            ),
        ]
    )
    return preprocessor, numeric_columns, categorical_columns


def _build_model_catalog(y: pd.Series) -> dict[str, Any]:
    class_count = y.nunique()
    catalog: dict[str, Any] = {
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=18,
            min_samples_leaf=1,
            random_state=42,
            class_weight="balanced",
        ),
        "decision_tree": DecisionTreeClassifier(
            max_depth=12,
            min_samples_leaf=2,
            random_state=42,
            class_weight="balanced",
        ),
        "logistic_regression": LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
        ),
        "svm": SVC(
            kernel="rbf",
            probability=True,
            class_weight="balanced",
            random_state=42,
        ),
        "ann": MLPClassifier(
            hidden_layer_sizes=(96, 48),
            activation="relu",
            learning_rate_init=0.001,
            max_iter=600,
            random_state=42,
        ),
    }

    return catalog


def _safe_auc(y_true: pd.Series, probabilities: np.ndarray, labels: list[str]) -> float | None:
    if len(labels) < 2:
        return None
    try:
        lb = LabelBinarizer()
        encoded = lb.fit_transform(y_true)
        if len(labels) == 2:
            if probabilities.ndim == 2 and probabilities.shape[1] > 1:
                return round(float(roc_auc_score(encoded, probabilities[:, 1])), 4)
            return None
        return round(float(roc_auc_score(encoded, probabilities, average="macro", multi_class="ovr")), 4)
    except Exception:
        return None


def _extract_feature_importance(model: Pipeline, feature_names: list[str]) -> list[dict[str, float]]:
    classifier = model.named_steps["classifier"]
    values = None
    if hasattr(classifier, "feature_importances_"):
        values = np.asarray(classifier.feature_importances_)
    elif hasattr(classifier, "coef_"):
        coef = np.asarray(classifier.coef_)
        values = np.mean(np.abs(coef), axis=0) if coef.ndim > 1 else np.abs(coef)

    if values is None:
        return []

    top_indices = np.argsort(values)[::-1][:8]
    return [
        {"feature": feature_names[index], "importance": round(float(values[index]), 4)}
        for index in top_indices
    ]


def _evaluate_model(
    pipeline: Pipeline,
    x_train: pd.DataFrame,
    y_train: pd.Series,
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, Any]:
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    probabilities = pipeline.predict_proba(x_test) if hasattr(pipeline, "predict_proba") else None
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )
    accuracy = accuracy_score(y_test, predictions)
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    labels = sorted(y_train.astype(str).unique().tolist())
    confusion = confusion_matrix(y_test, predictions, labels=labels).tolist()

    feature_names = pipeline.named_steps["preprocessor"].get_feature_names_out().tolist()
    importance = _extract_feature_importance(pipeline, feature_names)
    auc = _safe_auc(y_test, probabilities, labels) if probabilities is not None else None

    return {
        "pipeline": pipeline,
        "metrics": {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": auc,
        },
        "classification_report": report,
        "confusion_matrix": {"labels": labels, "matrix": confusion},
        "feature_importance": importance,
        "predictions_preview": [str(item) for item in predictions[:5]],
    }


def _choose_best_model(results: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    best_name = max(results, key=lambda name: results[name]["metrics"]["f1_score"])
    return best_name, results[best_name]


def _build_html_report(metadata: dict[str, Any], benchmark: dict[str, Any], report_path: Path) -> None:
    rows = []
    for model_name, payload in benchmark["models"].items():
        metrics = payload["metrics"]
        rows.append(
            "<tr>"
            f"<td>{model_name}</td>"
            f"<td>{metrics['accuracy']}</td>"
            f"<td>{metrics['precision']}</td>"
            f"<td>{metrics['recall']}</td>"
            f"<td>{metrics['f1_score']}</td>"
            f"<td>{metrics['roc_auc'] if metrics['roc_auc'] is not None else 'n/a'}</td>"
            "</tr>"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Cyber Attack Detection Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #0f172a; }}
    h1, h2 {{ margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
    th {{ background: #e2e8f0; }}
    .tag {{ display: inline-block; padding: 6px 10px; background: #dbeafe; border-radius: 999px; margin-right: 8px; }}
  </style>
</head>
<body>
  <h1>Cyber Attack Detection Report</h1>
  <p><strong>Dataset:</strong> {metadata['dataset_profile']} | <strong>Selected Model:</strong> {metadata['selected_model']}</p>
  <p><strong>Target Column:</strong> {metadata['target_column']} | <strong>Train/Test:</strong> {metadata['train_size']} / {metadata['test_size']}</p>
  <h2>Attack Categories</h2>
  <p>{"".join(f"<span class='tag'>{item}</span>" for item in metadata['classes'])}</p>
  <h2>Model Comparison</h2>
  <table>
    <thead>
      <tr>
        <th>Model</th>
        <th>Accuracy</th>
        <th>Precision</th>
        <th>Recall</th>
        <th>F1-Score</th>
        <th>ROC-AUC</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
    report_path.write_text(html, encoding="utf-8")


def train_model(csv_path: str, target_column: str, dataset_profile: str = "custom") -> dict[str, Any]:
    settings = get_settings()
    profile = _normalize_profile(dataset_profile)
    bundle = _load_dataset(csv_path, profile)
    frame = _prepare_profile_frame(bundle.frame, profile, target_column)
    frame = _engineer_features(frame)

    x = frame.drop(columns=["label"])
    y = frame["label"].astype(str)

    preprocessor, numeric_columns, categorical_columns = _build_preprocessor(x)
    model_catalog = _build_model_catalog(y)

    unique_classes = y.nunique()
    test_size = max(unique_classes, int(round(len(frame) * 0.3))) if len(frame) >= 12 else max(unique_classes, 2)
    if test_size >= len(frame):
        test_size = max(2, len(frame) // 3)
    test_size_ratio = test_size / len(frame)
    stratify = y if unique_classes > 1 and y.value_counts().min() > 1 and test_size >= unique_classes else None

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size_ratio,
        random_state=42,
        stratify=stratify,
    )

    benchmark_results: dict[str, dict[str, Any]] = {}
    for model_name, estimator in model_catalog.items():
        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", estimator),
            ]
        )
        benchmark_results[model_name] = _evaluate_model(pipeline, x_train, y_train, x_test, y_test)

    best_name, best_payload = _choose_best_model(benchmark_results)
    selected_pipeline = best_payload.pop("pipeline")

    settings.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(selected_pipeline, settings.model_path)

    benchmark = {
        "selected_model": best_name,
        "models": {
            name: {
                "metrics": payload["metrics"],
                "classification_report": payload["classification_report"],
                "confusion_matrix": payload["confusion_matrix"],
                "feature_importance": payload["feature_importance"],
                "predictions_preview": payload["predictions_preview"],
                "model_family": "deep-learning" if name == "ann" else "machine-learning",
            }
            for name, payload in benchmark_results.items()
        },
    }

    metadata = {
        "dataset_path": bundle.dataset_path,
        "dataset_profile": profile,
        "target_column": "label",
        "feature_columns": x.columns.tolist(),
        "categorical_columns": categorical_columns,
        "numeric_columns": numeric_columns,
        "classes": sorted(y.unique().tolist()),
        "train_size": int(len(x_train)),
        "test_size": int(len(x_test)),
        "selected_model": best_name,
        "accuracy": benchmark["models"][best_name]["metrics"]["accuracy"],
        "feature_importance": benchmark["models"][best_name]["feature_importance"],
        "attack_explanations": ATTACK_EXPLANATIONS,
    }

    report = {
        "selected_model": best_name,
        "selected_model_metrics": benchmark["models"][best_name]["metrics"],
        "selected_model_classification_report": benchmark["models"][best_name]["classification_report"],
        "selected_model_confusion_matrix": benchmark["models"][best_name]["confusion_matrix"],
        "benchmark": benchmark,
    }

    settings.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    settings.report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_report_path = settings.report_path.with_suffix(".html")
    _build_html_report(metadata, benchmark, html_report_path)

    return {
        "metadata": metadata,
        "report": report,
        "benchmark": benchmark,
        "html_report_path": str(html_report_path),
        "dataset_profiles": DATASET_PROFILES,
    }
