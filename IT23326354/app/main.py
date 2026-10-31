"""
main.py — FastAPI Application for SDN Flow DoS Detection REST API
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from app.predictor import DoSPredictor
from app.schemas import ErrorResponse, FlowFeatures, HealthResponse, PredictionResponse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("api")

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "xgboost_model.joblib"
PREPROCESSOR_PATH = BASE_DIR / "models" / "preprocessor.joblib"
SCHEMA_PATH = BASE_DIR / "configs" / "feature_schema.json"

START_TIME = time.time()
predictor: DoSPredictor = None


def get_predictor() -> DoSPredictor:
    """Lazy loader guaranteeing predictor is available in both lifespan and test client modes."""
    global predictor
    if predictor is None:
        predictor = DoSPredictor(
            model_path=MODEL_PATH,
            preprocessor_path=PREPROCESSOR_PATH,
            schema_path=SCHEMA_PATH,
        )
    return predictor


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load model once on startup and cleanly release resources on shutdown.
    """
    logger.info("Initializing DoS Detection service...")
    p = get_predictor()
    if p.is_loaded:
        logger.info("XGBoost model successfully loaded and warm.")
    else:
        logger.warning(f"Predictor initialized in degraded mode: {p.load_error}")
    yield
    logger.info("Shutting down DoS Detection service.")


app = FastAPI(
    title="SDN Flow DoS Detection REST API",
    description=(
        "Lightweight machine learning DoS detection service for IoMT networks (Project J26-CS-330). "
        "Consumes OpenFlow flow statistics metadata and outputs Normal vs DoS classifications "
        "for automated zero-touch mitigation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for cross-module integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    """
    Middleware measuring total HTTP request-response cycle time.
    """
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start_time) * 1000.0
    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.2f}"
    return response


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root path to interactive Dashboard."""
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    """Serve the interactive SOC DoS Detection Dashboard."""
    dash_path = BASE_DIR / "app" / "dashboard.html"
    return FileResponse(dash_path)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check and model status",
    tags=["System"],
)
async def health_check():
    """
    Check the running state of the service and verify model availability.
    """
    p = get_predictor()
    uptime = time.time() - START_TIME
    model_loaded = bool(p and p.is_loaded)
    status_str = "ok" if model_loaded else "degraded"
    feature_count = len(p.feature_names) if p else 0

    return HealthResponse(
        status=status_str,
        model_loaded=model_loaded,
        model_path=str(MODEL_PATH),
        feature_count=feature_count,
        uptime_seconds=round(uptime, 2),
    )


@app.post(
    "/predict",
    response_model=PredictionResponse,
    responses={
        503: {"model": ErrorResponse, "description": "Model not loaded"},
        422: {"description": "Validation error"},
    },
    summary="Classify flow statistics as Normal or DoS",
    tags=["Detection"],
)
async def predict_flow(payload: FlowFeatures):
    """
    Accepts flow-statistics metadata, executes inference via the trained XGBoost model,
    and returns a structured detection alert for the Mitigation Component.
    """
    p = get_predictor()
    if not p or not p.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Detection engine unavailable: {p.load_error if p else 'Not initialized'}",
        )

    try:
        data_dict = payload.model_dump(by_alias=True)
        result = p.predict(data_dict)
        logger.info(
            f"Prediction: {result['prediction']} | Confidence: {result['confidence']} | Latency: {result['inference_latency_ms']} ms"
        )
        return PredictionResponse(**result)
    except Exception as e:
        logger.exception("Error during prediction inference")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}",
        )
