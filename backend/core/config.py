"""
Configuration management for Argus XDR.
Handles environment variables, model paths, and application settings.
"""

import os
from pathlib import Path
from typing import Optional
from functools import lru_cache

from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    # Database
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")  # Direct Postgres connection (optional)
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", "40"))

    # Model Configuration
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    RERANKER_MODEL: str = os.getenv("RERANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
    EMBEDDING_DIMENSION: int = int(os.getenv("EMBEDDING_DIMENSION", "384"))  # MiniLM output size

    # Model Cache
    HF_HOME: str = os.getenv("HF_HOME", str(Path.home() / ".cache" / "huggingface"))
    TORCH_HOME: str = os.getenv("TORCH_HOME", str(Path.home() / ".cache" / "torch"))

    # LLM Configuration (for post-MVP agent)
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openrouter")  # openrouter, openai, groq
    LLM_API_KEY: Optional[str] = os.getenv("LLM_API_KEY")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "openrouter/meta-llama/llama-2-70b-chat")

    # Application Configuration
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Server Configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # RAG Configuration
    KNOWLEDGE_BASE_SIZE: int = int(os.getenv("KNOWLEDGE_BASE_SIZE", "100"))
    TOP_K_RETRIEVAL: int = int(os.getenv("TOP_K_RETRIEVAL", "5"))
    SIMILARITY_THRESHOLD: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.3"))

    # Feature Flags
    ENABLE_RERANKING: bool = os.getenv("ENABLE_RERANKING", "True").lower() == "true"
    ENABLE_HYBRID_SEARCH: bool = os.getenv("ENABLE_HYBRID_SEARCH", "True").lower() == "true"

    def validate(self) -> None:
        """Validate critical configuration parameters."""
        if not self.SUPABASE_URL or not self.SUPABASE_KEY:
            raise ValueError(
                "SUPABASE_URL and SUPABASE_KEY environment variables are required"
            )

    def to_dict(self) -> dict:
        """Convert settings to dictionary."""
        return {
            key: getattr(self, key)
            for key in dir(self)
            if not key.startswith("_") and key.isupper() and not callable(getattr(self, key))
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Get application settings (singleton pattern with caching).

    Returns:
        Settings: Validated application configuration

    Raises:
        ValueError: If required environment variables are missing
    """
    settings = Settings()
    settings.validate()
    return settings


# Initialize settings on module import
settings = get_settings()
