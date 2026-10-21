"""
API Endpoints Implementation for Reconnaissance Intrusion Detection Service.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
import numpy as np
import pandas as pd
import psutil

from src.alerts.engine import AlertEngine
from src.alerts.repository import SQLiteAlertRepository
from src.api.schemas import (
    BatchFlowPayload,
    BatchPredictionResponse,
    FlowFeaturesPayload,
    ModelInfoResponse,
    PredictionResponse,
)
from src.data.schema import (
    CANONICAL_TO_BINARY_MAP,
    CLASS_TO_INT_MAP,
    FEATURE_GROUPS,
    INT_TO_CLASS_MAP,
    TARGET_CLASSES,
)
from src.integration.sdn_client import SDNMitigationClient

logger = logging.getLogger(__name__)

router = APIRouter()

# Global runtime state populated on application startup
runtime_state: Dict[str, Any] = {
    "pipeline": None,
    "model_name": "LightGBM",
    "model_version": "v1.0.0",
    "alert_engine": AlertEngine(),
    "alert_repo": SQLiteAlertRepository(),
    "sdn_client": SDNMitigationClient(),
    "start_time": time.time(),
    "total_predictions": 0,
    "total_alerts": 0,
}


@router.get("/health", tags=["System"])
def get_health():
    uptime = time.time() - runtime_state["start_time"]
    return {
        "status": "healthy",
        "service": "Multi-Class Reconnaissance IDS",
        "model_loaded": runtime_state["pipeline"] is not None,
        "model_version": runtime_state["model_version"],
        "uptime_seconds": round(uptime, 2),
        "total_predictions": runtime_state["total_predictions"],
        "total_alerts_generated": runtime_state["total_alerts"],
    }


@router.get("/model/info", response_model=ModelInfoResponse, tags=["Model"])
def get_model_info():
    pipeline = runtime_state["pipeline"]
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Model pipeline is not loaded.")

    return ModelInfoResponse(
        model_name="Champion Reconnaissance Detector",
        model_version=runtime_state["model_version"],
        champion_algorithm=runtime_state["model_name"],
        selected_feature_count=len(pipeline.selected_features),
        selected_features=pipeline.selected_features,
        target_classes=TARGET_CLASSES,
        status="ACTIVE",
    )


@router.get("/features", tags=["Model"])
def get_features():
    pipeline = runtime_state["pipeline"]
    selected = pipeline.selected_features if pipeline else []
    return {
        "selected_feature_count": len(selected),
        "selected_features": selected,
        "expected_order": selected,
        "feature_taxonomy_groups": FEATURE_GROUPS,
    }


@router.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict_single_flow(payload: FlowFeaturesPayload):
    pipeline = runtime_state["pipeline"]
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Model pipeline is not loaded.")

    flow_dict = payload.model_dump(by_alias=True)
    df_single = pd.DataFrame([flow_dict])

    # Model inference
    preds = pipeline.predict(df_single)
    probas = pipeline.predict_proba(df_single)

    pred_idx = int(preds[0])
    pred_class = INT_TO_CLASS_MAP.get(pred_idx, "Benign")
    confidence = float(probas[0, pred_idx])

    prob_dict = {INT_TO_CLASS_MAP[i]: round(float(probas[0, i]), 4) for i in range(len(TARGET_CLASSES))}

    runtime_state["total_predictions"] += 1

    # Confidence and severity mapping
    engine: AlertEngine = runtime_state["alert_engine"]
    alert_repo: SQLiteAlertRepository = runtime_state["alert_repo"]
    sdn_client: SDNMitigationClient = runtime_state["sdn_client"]

    alert_obj = engine.create_alert_object(
        predicted_class=pred_class,
        confidence=confidence,
        flow_id=payload.flow_id,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        destination_port=payload.destination_port,
        is_critical_asset=payload.is_critical_asset or False,
        model_version=runtime_state["model_version"],
        raw_features=flow_dict,
    )

    alert_id = None
    severity = "INFO" if pred_class == "Benign" else "LOW"

    if alert_obj:
        alert_id = alert_obj["alert_id"]
        severity = alert_obj["severity"]
        runtime_state["total_alerts"] += 1

        # Save to database
        alert_repo.save_alert(alert_obj)

        # Dispatch to SDN Mitigation if eligible
        if alert_obj["status"] in ("CONFIRMED", "MITIGATION_ELIGIBLE"):
            dispatch_result = sdn_client.send_alert(alert_obj)
            status_val = dispatch_result.get("status", "FAILED")
            action_val = dispatch_result.get("controller_ack", {}).get("mitigation_action", "NONE")
            alert_repo.update_delivery_status(alert_id, status_val, action_val)

    return PredictionResponse(
        prediction=pred_class,
        attack_type="Benign" if pred_class == "Benign" else "Reconnaissance",
        recon_subtype=pred_class,
        confidence=round(confidence, 4),
        severity=severity,
        timestamp=datetime.now(timezone.utc).isoformat(),
        flow_id=payload.flow_id or f"flow-{int(time.time()*1000)}",
        model_version=runtime_state["model_version"],
        alert_id=alert_id,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        probabilities=prob_dict,
    )


@router.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Prediction"])
def predict_batch_flows(batch: BatchFlowPayload):
    pipeline = runtime_state["pipeline"]
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Model pipeline is not loaded.")

    if not batch.flows:
        return BatchPredictionResponse(count=0, predictions=[], processing_time_ms=0.0)

    t0 = time.perf_counter()
    raw_dicts = [f.model_dump(by_alias=True) for f in batch.flows]
    df_batch = pd.DataFrame(raw_dicts)

    preds = pipeline.predict(df_batch)
    probas = pipeline.predict_proba(df_batch)

    engine: AlertEngine = runtime_state["alert_engine"]
    alert_repo: SQLiteAlertRepository = runtime_state["alert_repo"]

    responses: List[PredictionResponse] = []
    for i, flow_payload in enumerate(batch.flows):
        pred_idx = int(preds[i])
        pred_class = INT_TO_CLASS_MAP.get(pred_idx, "Benign")
        confidence = float(probas[i, pred_idx])
        prob_dict = {INT_TO_CLASS_MAP[j]: round(float(probas[i, j]), 4) for j in range(len(TARGET_CLASSES))}

        alert_obj = engine.create_alert_object(
            predicted_class=pred_class,
            confidence=confidence,
            flow_id=flow_payload.flow_id,
            source_ip=flow_payload.source_ip,
            destination_ip=flow_payload.destination_ip,
            destination_port=flow_payload.destination_port,
            is_critical_asset=flow_payload.is_critical_asset or False,
            model_version=runtime_state["model_version"],
        )

        alert_id = None
        severity = "INFO" if pred_class == "Benign" else "LOW"
        if alert_obj:
            alert_id = alert_obj["alert_id"]
            severity = alert_obj["severity"]
            alert_repo.save_alert(alert_obj)
            runtime_state["total_alerts"] += 1

        responses.append(
            PredictionResponse(
                prediction=pred_class,
                attack_type="Benign" if pred_class == "Benign" else "Reconnaissance",
                recon_subtype=pred_class,
                confidence=round(confidence, 4),
                severity=severity,
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow_payload.flow_id or f"flow-b-{i}",
                model_version=runtime_state["model_version"],
                alert_id=alert_id,
                source_ip=flow_payload.source_ip,
                destination_ip=flow_payload.destination_ip,
                probabilities=prob_dict,
            )
        )

    runtime_state["total_predictions"] += len(batch.flows)
    proc_ms = (time.perf_counter() - t0) * 1000.0

    return BatchPredictionResponse(
        count=len(responses),
        predictions=responses,
        processing_time_ms=round(proc_ms, 2),
    )


@router.get("/alerts", tags=["Alerts"])
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = Query(default=None),
    min_confidence: Optional[float] = Query(default=None, ge=0.0, le=1.0),
):
    repo: SQLiteAlertRepository = runtime_state["alert_repo"]
    alerts = repo.list_alerts(limit=limit, offset=offset, severity=severity, min_confidence=min_confidence)
    return {"count": len(alerts), "alerts": alerts}


@router.get("/alerts/{alert_id}", tags=["Alerts"])
def get_alert_by_id(alert_id: str):
    repo: SQLiteAlertRepository = runtime_state["alert_repo"]
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@router.get("/metrics", tags=["System"])
def get_system_metrics():
    proc = psutil.Process()
    ram_info = proc.memory_info()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_predictions": runtime_state["total_predictions"],
        "total_alerts": runtime_state["total_alerts"],
        "ram_rss_mb": round(ram_info.rss / (1024 * 1024), 2),
        "cpu_percent": proc.cpu_percent(interval=0.1),
        "open_threads": proc.num_threads(),
    }
