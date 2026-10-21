"""
FastAPI Main Application Gateway for Reconnaissance Intrusion Detection.
Handles startup lifecycle, model loading, and routes registration.
"""

from contextlib import asynccontextmanager
import logging
import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib

# Ensure module visibility
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.api.routes import router, runtime_state
from src.features.preprocessor import ReconFlowPreprocessor
from src.models.pipeline import CompleteInferencePipeline

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s",
)
logger = logging.getLogger("ReconAPI")


def load_champion_model_if_needed():
    if runtime_state.get("pipeline") is not None:
        return runtime_state["pipeline"]
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    model_path = os.path.join(base_dir, "models", "champion_pipeline.joblib")
    if os.path.exists(model_path):
        try:
            pipeline = joblib.load(model_path)
            runtime_state["pipeline"] = pipeline
            runtime_state["model_name"] = pipeline.model.__class__.__name__
            logger.info(f"Loaded champion model: {runtime_state['model_name']} with {len(pipeline.selected_features)} features.")
            return pipeline
        except Exception as e:
            logger.error(f"Failed to load champion pipeline: {e}")
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_champion_model_if_needed()
    yield
    logger.info("Shutting down Reconnaissance IDS API Gateway...")


# Preload champion model on import
load_champion_model_if_needed()


app = FastAPI(
    title="Lightweight IoMT Reconnaissance Intrusion Detection Service",
    description=(
        "Production-grade, confidence-aware REST API for detecting and classifying "
        "multi-class reconnaissance attacks (Ping Sweep, Port Scan, OS Scan, Vulnerability Scan) "
        "in Internet of Medical Things (IoMT) networks using CICIoMT2024 benchmark data."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Enable CORS for local demo dashboard and team integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static dashboard assets
dashboard_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_dir):
    app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")

    @app.get("/", include_in_schema=False)
    def root_dashboard():
        return FileResponse(os.path.join(dashboard_dir, "index.html"))

app.include_router(router)
