from typing import Any

from pydantic import BaseModel, Field


class NetworkRecord(BaseModel):
    duration: float = Field(default=0.0, description="Connection duration in seconds")
    src_bytes: float = Field(default=0.0)
    dst_bytes: float = Field(default=0.0)
    count: float = Field(default=0.0, description="Connections to same host")
    srv_count: float = Field(default=0.0, description="Connections to same service")
    same_srv_rate: float = Field(default=0.0)
    diff_srv_rate: float = Field(default=0.0)
    dst_host_count: float = Field(default=0.0)
    dst_host_srv_count: float = Field(default=0.0)
    protocol_type: str = Field(default="tcp")
    service: str = Field(default="http")
    flag: str = Field(default="SF")


class PredictRequest(BaseModel):
    records: list[NetworkRecord]
    explain: bool = True


class FeatureContribution(BaseModel):
    feature: str
    value: str
    note: str


class RecordPrediction(BaseModel):
    label: str
    confidence: float
    severity: str
    probabilities: dict[str, float]
    attack_description: str | None = None
    mitigation: list[str] = Field(default_factory=list)
    top_contributors: list[FeatureContribution] = Field(default_factory=list)


class DatasetSummary(BaseModel):
    total_records: int
    malicious_records: int
    benign_records: int
    attack_distribution: dict[str, int]
    highest_severity: str


class ChartPoint(BaseModel):
    label: str
    value: float


class AlertEvent(BaseModel):
    sequence: int
    label: str
    severity: str
    confidence: float
    message: str


class DashboardInsights(BaseModel):
    severity_breakdown: dict[str, int]
    confidence_bands: list[ChartPoint]
    timeline: list[AlertEvent]
    recent_alerts: list[AlertEvent]


class PredictResponse(BaseModel):
    summary: DatasetSummary
    predictions: list[RecordPrediction]
    assistant_summary: str | None = None
    remediation: list[str] = Field(default_factory=list)
    dashboard: DashboardInsights | None = None


class SavedAnalysisResponse(BaseModel):
    has_data: bool
    state: PredictResponse | None = None


class TrainRequest(BaseModel):
    csv_path: str = Field(
        default="data/network_traffic_sample.csv",
        description="Local dataset path containing a label column",
    )
    target_column: str = Field(default="label")
    dataset_profile: str = Field(default="custom")


class ModelStatusResponse(BaseModel):
    ready: bool
    model_path: str
    llm_enabled: bool = False
    metadata: dict[str, Any] | None = None


class BenchmarkResponse(BaseModel):
    selected_model: str
    models: dict[str, Any]


class DatasetProfilesResponse(BaseModel):
    profiles: dict[str, str]


class ReportResponse(BaseModel):
    metadata: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    html_report_path: str | None = None


class ChatMessage(BaseModel):
    role: str = Field(description="chat role such as user or assistant")
    content: str = Field(min_length=1, description="message content")


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, description="latest user prompt")
    history: list[ChatMessage] = Field(default_factory=list)
    latest_summary: DatasetSummary | None = None


class ChatResponse(BaseModel):
    reply: str
