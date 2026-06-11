import io
import json
import logging

import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from app.db.database import get_db
from app.models.user import User, UserAnalysisState
from app.schemas.prediction import (
    BenchmarkResponse,
    ChatRequest,
    ChatResponse,
    DatasetProfilesResponse,
    ModelStatusResponse,
    PredictRequest,
    PredictResponse,
    ReportResponse,
    SavedAnalysisResponse,
    TrainRequest,
    DatasetSummary,
    RecordPrediction,
)
from app.services.assistant_service import assistant_service
from app.services.model_service import model_service
from app.services.training_service import DATASET_PROFILES, train_model
from app.api.auth import get_current_user

router = APIRouter(prefix="/api/v1", dependencies=[Depends(get_current_user)])

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _merge_summary(existing: dict | None, incoming: DatasetSummary) -> dict:
    if not existing:
        return incoming.model_dump()

    distribution = dict(existing.get("attack_distribution") or {})
    for label, count in incoming.attack_distribution.items():
        distribution[label] = distribution.get(label, 0) + count

    existing_highest = str(existing.get("highest_severity") or "low").lower()
    incoming_highest = incoming.highest_severity.lower()
    highest = incoming_highest if SEVERITY_RANK.get(incoming_highest, -1) > SEVERITY_RANK.get(existing_highest, -1) else existing_highest

    return {
        "total_records": int(existing.get("total_records") or 0) + incoming.total_records,
        "malicious_records": int(existing.get("malicious_records") or 0) + incoming.malicious_records,
        "benign_records": int(existing.get("benign_records") or 0) + incoming.benign_records,
        "attack_distribution": distribution,
        "highest_severity": highest,
    }


def _dashboard_from_predictions(prediction_payloads: list[dict]):
    predictions = [RecordPrediction(**item) for item in prediction_payloads]
    return model_service._dashboard_payload(predictions).model_dump() if predictions else None


def _save_user_analysis_state(
    db: Session,
    current_user: User,
    response: PredictResponse,
) -> None:
    state = db.query(UserAnalysisState).filter(UserAnalysisState.user_id == current_user.id).first()
    incoming_predictions = [item.model_dump() for item in response.predictions]

    if state is None:
        prediction_payloads = incoming_predictions[:1000]
        state = UserAnalysisState(
            user_id=current_user.id,
            summary=response.summary.model_dump(),
            predictions=prediction_payloads,
            dashboard=_dashboard_from_predictions(prediction_payloads),
            assistant_summary=response.assistant_summary,
            remediation=response.remediation,
        )
        db.add(state)
    else:
        prediction_payloads = (incoming_predictions + list(state.predictions or []))[:1000]
        state.summary = _merge_summary(state.summary, response.summary)
        state.predictions = prediction_payloads
        state.dashboard = _dashboard_from_predictions(prediction_payloads)
        state.assistant_summary = response.assistant_summary or state.assistant_summary
        state.remediation = response.remediation or state.remediation

    db.commit()


def _state_to_response(state: UserAnalysisState) -> PredictResponse:
    return PredictResponse(
        summary=DatasetSummary(**state.summary),
        predictions=[RecordPrediction(**item) for item in (state.predictions or [])],
        assistant_summary=state.assistant_summary,
        remediation=state.remediation or [],
        dashboard=state.dashboard,
    )


@router.get("/health")
def health_check() -> dict:
    return {"status": "ok", "model_ready": model_service.is_ready}


@router.get("/model/status", response_model=ModelStatusResponse)
def model_status() -> ModelStatusResponse:
    return ModelStatusResponse(**model_service.status_payload())


@router.get("/dataset/profiles", response_model=DatasetProfilesResponse)
def dataset_profiles() -> DatasetProfilesResponse:
    return DatasetProfilesResponse(profiles=DATASET_PROFILES)


@router.get("/report", response_model=ReportResponse)
def report_endpoint() -> ReportResponse:
    return ReportResponse(**model_service.report_payload())


@router.get("/report/html")
def html_report_download():
    report_path = model_service.settings.report_path.with_suffix(".html")
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="HTML report not available. Train the model first.")
    return FileResponse(report_path)


@router.get("/benchmark", response_model=BenchmarkResponse)
def benchmark_endpoint() -> BenchmarkResponse:
    payload = model_service.report_payload().get("report") or {}
    benchmark = payload.get("benchmark")
    if not benchmark:
        raise HTTPException(status_code=404, detail="Benchmark report not available. Train the model first.")
    return BenchmarkResponse(**benchmark)


@router.get("/analysis/state", response_model=SavedAnalysisResponse)
def saved_analysis_state(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SavedAnalysisResponse:
    state = db.query(UserAnalysisState).filter(UserAnalysisState.user_id == current_user.id).first()
    if state is None:
        return SavedAnalysisResponse(has_data=False, state=None)
    return SavedAnalysisResponse(has_data=True, state=_state_to_response(state))


@router.delete("/analysis/state")
def clear_analysis_state(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    state = db.query(UserAnalysisState).filter(UserAnalysisState.user_id == current_user.id).first()
    if state is not None:
        db.delete(state)
        db.commit()
    return {"message": "Analysis state cleared"}


@router.post("/train")
async def train_endpoint(payload: TrainRequest) -> dict:
    try:
        result = await run_in_threadpool(train_model, payload.csv_path, payload.target_column, payload.dataset_profile)
        model_service.refresh()
        return {"message": "Training completed successfully", **result}
    except Exception as exc:
        logger.exception("Error during model training")
        raise HTTPException(status_code=500, detail="An internal error occurred during training.") from exc


@router.post("/predict", response_model=PredictResponse)
async def predict_endpoint(
    payload: PredictRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PredictResponse:
    try:
        predictions, summary, dashboard = await run_in_threadpool(model_service.predict, payload.records)
        assistant_payload = {"assistant_summary": None, "remediation": []}
        if payload.explain:
            assistant_payload = await run_in_threadpool(assistant_service.analyze, summary, predictions)
        response = PredictResponse(
            summary=summary,
            predictions=predictions,
            assistant_summary=assistant_payload["assistant_summary"],
            remediation=assistant_payload["remediation"],
            dashboard=dashboard,
        )
        _save_user_analysis_state(db, current_user, response)
        return response
    except Exception as exc:
        logger.exception("Error during prediction")
        raise HTTPException(status_code=500, detail="An internal error occurred during prediction.") from exc


@router.post("/predict/csv", response_model=PredictResponse)
async def predict_csv_endpoint(
    file: UploadFile = File(...),
    explain: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 10MB.")
    try:
        content = await file.read()
        frame = pd.read_csv(io.StringIO(content.decode("utf-8")))
        required = [
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
        ]
        missing = [column for column in required if column not in frame.columns]
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")

        payload = PredictRequest(records=json.loads(frame[required].to_json(orient="records")), explain=explain)
        predictions, summary, dashboard = await run_in_threadpool(model_service.predict, payload.records)
        assistant_payload = {"assistant_summary": None, "remediation": []}
        if explain:
            assistant_payload = await run_in_threadpool(assistant_service.analyze, summary, predictions)
        response = PredictResponse(
            summary=summary,
            predictions=predictions,
            assistant_summary=assistant_payload["assistant_summary"],
            remediation=assistant_payload["remediation"],
            dashboard=dashboard,
        )
        _save_user_analysis_state(db, current_user, response)
        return response
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error during CSV prediction")
        raise HTTPException(status_code=500, detail="An internal error occurred during CSV prediction.") from exc


@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(payload: ChatRequest) -> ChatResponse:
    try:
        result = await run_in_threadpool(
            assistant_service.chat,
            message=payload.message,
            history=payload.history,
            latest_summary=payload.latest_summary,
        )
        return ChatResponse(**result)
    except Exception as exc:
        logger.exception("Error during chat")
        raise HTTPException(status_code=400, detail=str(exc)) from exc
