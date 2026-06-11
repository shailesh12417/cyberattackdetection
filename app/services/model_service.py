import json
import logging
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.core.config import get_settings
from app.schemas.prediction import (
    AlertEvent,
    ChartPoint,
    DashboardInsights,
    DatasetSummary,
    FeatureContribution,
    NetworkRecord,
    RecordPrediction,
)
from app.services.assistant_service import assistant_service


logger = logging.getLogger(__name__)


SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_MAP = {
    "normal": "low",
    "benign": "low",
    "probe": "medium",
    "dos": "high",
    "u2r": "critical",
    "r2l": "critical",
}

ATTACK_GUIDANCE = {
    "normal": ["Continue baseline monitoring and store this flow as reference traffic."],
    "probe": [
        "Inspect source hosts for scanning behavior across services and ports.",
        "Tune IDS rules for reconnaissance and repeated discovery attempts.",
    ],
    "dos": [
        "Rate-limit or block the suspected sources at firewall or edge controls.",
        "Check server capacity, packet rates, and repeated connection bursts.",
    ],
    "r2l": [
        "Review authentication logs and suspicious credential usage from remote clients.",
        "Audit exposed services and reset potentially compromised user accounts.",
    ],
    "u2r": [
        "Inspect privilege-escalation logs, shell activity, and process execution history.",
        "Isolate the host and validate whether administrative access was abused.",
    ],
}


class ModelService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.model = None
        self.metadata: dict[str, Any] | None = None
        self.report: dict[str, Any] | None = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        self.model = None
        self.metadata = None
        self.report = None
        if self.settings.model_path.exists():
            try:
                self.model = joblib.load(self.settings.model_path)
            except Exception as exc:
                logger.warning("Unable to load model artifact from %s: %s", self.settings.model_path, exc)
        if self.settings.metadata_path.exists():
            try:
                self.metadata = json.loads(self.settings.metadata_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Unable to load metadata from %s: %s", self.settings.metadata_path, exc)
        if self.settings.report_path.exists():
            try:
                self.report = json.loads(self.settings.report_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Unable to load report from %s: %s", self.settings.report_path, exc)

    def refresh(self) -> None:
        self._load_artifacts()

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.metadata is not None

    def _to_frame(self, records: list[NetworkRecord]) -> pd.DataFrame:
        frame = pd.DataFrame([record.model_dump() for record in records])
        frame["total_bytes"] = frame["src_bytes"] + frame["dst_bytes"]
        frame["byte_ratio"] = frame.apply(
            lambda row: row["src_bytes"] / (row["dst_bytes"] + 1) if row["dst_bytes"] > 0 else row["src_bytes"],
            axis=1,
        )
        frame["connection_pressure"] = frame["count"] + frame["srv_count"] + frame["dst_host_count"]
        frame["service_diversity"] = frame["diff_srv_rate"] - frame["same_srv_rate"]
        frame["host_service_balance"] = frame.apply(
            lambda row: row["dst_host_srv_count"] / (row["dst_host_count"] + 1) if row["dst_host_count"] > 0 else 0,
            axis=1,
        )
        frame["is_zero_payload"] = ((frame["src_bytes"] + frame["dst_bytes"]) == 0).astype(int)
        return frame

    def _top_contributors(self, row: pd.Series) -> list[FeatureContribution]:
        signals = []
        if row["count"] > 100:
            signals.append(("count", row["count"], "High repeated connection count suggests flood or scan activity."))
        if row["same_srv_rate"] < 0.2 and row["diff_srv_rate"] > 0.6:
            signals.append(("diff_srv_rate", row["diff_srv_rate"], "Large service diversity can indicate scanning or reconnaissance."))
        if row["src_bytes"] == 0 and row["dst_bytes"] == 0:
            signals.append(("src_bytes/dst_bytes", "0/0", "Zero-payload repeated flows often align with failed or probing connections."))
        if row["dst_host_count"] > 120:
            signals.append(("dst_host_count", row["dst_host_count"], "Large destination-host volume can signal broad probing or attack spread."))
        if row["service"] in {"telnet", "exec", "shell"}:
            signals.append(("service", row["service"], "Sensitive service exposure increases attack likelihood."))
        return [FeatureContribution(feature=name, value=str(value), note=note) for name, value, note in signals[:3]]

    def _dashboard_payload(self, predictions: list[RecordPrediction]) -> DashboardInsights:
        severity_breakdown: dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
        confidence_bands = {
            "0.00-0.49": 0,
            "0.50-0.69": 0,
            "0.70-0.84": 0,
            "0.85-1.00": 0,
        }
        timeline: list[AlertEvent] = []

        for index, prediction in enumerate(predictions, start=1):
            severity_breakdown[prediction.severity] = severity_breakdown.get(prediction.severity, 0) + 1
            score = prediction.confidence
            if score < 0.5:
                confidence_bands["0.00-0.49"] += 1
            elif score < 0.7:
                confidence_bands["0.50-0.69"] += 1
            elif score < 0.85:
                confidence_bands["0.70-0.84"] += 1
            else:
                confidence_bands["0.85-1.00"] += 1

            timeline.append(
                AlertEvent(
                    sequence=index,
                    label=prediction.label,
                    severity=prediction.severity,
                    confidence=prediction.confidence,
                    message=f"{prediction.label.upper()} detected with {prediction.confidence:.2f} confidence.",
                )
            )

        recent_alerts = [item for item in timeline if item.severity in {"high", "critical"}][-5:]
        return DashboardInsights(
            severity_breakdown=severity_breakdown,
            confidence_bands=[ChartPoint(label=label, value=value) for label, value in confidence_bands.items()],
            timeline=timeline,
            recent_alerts=recent_alerts or timeline[-5:],
        )

    def predict(self, records: list[NetworkRecord]) -> tuple[list[RecordPrediction], DatasetSummary, DashboardInsights]:
        if not self.is_ready:
            raise RuntimeError("Model artifacts are not available. Train the model first.")

        frame = self._to_frame(records)
        labels = self.model.predict(frame)
        probabilities = self.model.predict_proba(frame)
        classes = list(self.model.classes_)

        results: list[RecordPrediction] = []
        attack_distribution: dict[str, int] = {}
        highest_index = -1
        explanations = (self.metadata or {}).get("attack_explanations", {})

        for row, label, row_probs in zip(frame.to_dict(orient="records"), labels, probabilities):
            score_map = {cls: round(float(prob), 4) for cls, prob in zip(classes, row_probs)}
            confidence = max(score_map.values())
            label_name = str(label).lower()
            severity = SEVERITY_MAP.get(label_name, "medium")
            highest_index = max(highest_index, SEVERITY_ORDER.index(severity))
            attack_distribution[label_name] = attack_distribution.get(label_name, 0) + 1
            row_series = pd.Series(row)
            results.append(
                RecordPrediction(
                    label=label_name,
                    confidence=round(confidence, 4),
                    severity=severity,
                    probabilities=score_map,
                    attack_description=explanations.get(label_name),
                    mitigation=ATTACK_GUIDANCE.get(label_name, ["Investigate the flow and validate supporting logs."]),
                    top_contributors=self._top_contributors(row_series),
                )
            )

        benign_records = attack_distribution.get("normal", 0) + attack_distribution.get("benign", 0)
        total_records = len(results)
        malicious_records = total_records - benign_records
        summary = DatasetSummary(
            total_records=total_records,
            malicious_records=malicious_records,
            benign_records=benign_records,
            attack_distribution=attack_distribution,
            highest_severity=SEVERITY_ORDER[highest_index] if highest_index >= 0 else "—",
        )
        dashboard = self._dashboard_payload(results)
        return results, summary, dashboard

    def status_payload(self) -> dict[str, Any]:
        return {
            "ready": self.is_ready,
            "model_path": str(self.settings.model_path),
            "llm_enabled": assistant_service.llm_enabled,
            "metadata": self.metadata,
        }

    def report_payload(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "report": self.report,
            "html_report_path": str(self.settings.report_path.with_suffix(".html")),
        }


model_service = ModelService()
