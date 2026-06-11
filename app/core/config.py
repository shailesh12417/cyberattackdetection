from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = Field(default="Cyber Attack Detection Platform", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    allowed_origins: str = Field(
        default="http://localhost:8000,http://127.0.0.1:8000",
        alias="ALLOWED_ORIGINS",
    )
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")
    model_path: Path = Field(default=BASE_DIR / "artifacts" / "model.joblib", alias="MODEL_PATH")
    metadata_path: Path = Field(
        default=BASE_DIR / "artifacts" / "metadata.json",
        alias="METADATA_PATH",
    )
    report_path: Path = Field(default=BASE_DIR / "artifacts" / "report.json", alias="REPORT_PATH")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
    )

    @property
    def allowed_origins_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
