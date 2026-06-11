from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import BASE_DIR, get_settings
from app.core.logging import configure_logging
from app.services.model_service import model_service
from app.services.training_service import DEFAULT_DATASET, train_model
from app.api.auth import router as auth_router
from app.db.database import Base, engine


settings = get_settings()
configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Initialize the database tables
    Base.metadata.create_all(bind=engine)
    # Auto-train is disabled to ensure fast startup.
    # Users can trigger training via the dashboard.
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

static_dir = BASE_DIR / "frontend"
assets_dir = static_dir / "assets"
assets_dir.mkdir(parents=True, exist_ok=True)

app.include_router(router)
app.include_router(auth_router)
app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/", include_in_schema=False)
def serve_frontend():
    return FileResponse(static_dir / "index.html")


@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    return FileResponse(static_dir / "index.html")

@app.get("/index.html", include_in_schema=False)
def serve_index_html():
    return FileResponse(static_dir / "index.html")

@app.get("/auth.html", include_in_schema=False)
def serve_auth():
    return FileResponse(static_dir / "auth.html")
