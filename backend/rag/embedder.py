"""
Embedder module for Argus XDR.
Generates embeddings for security events and threat intelligence.
Reuses lazy-loading singleton pattern from RV32I project.
"""

import logging
import os
from typing import Optional, Union
from functools import lru_cache

try:
    from sentence_transformers import SentenceTransformer
    import torch
except ImportError:
    raise ImportError(
        "sentence-transformers library is required. "
        "Install with: pip install sentence-transformers torch"
    )

from backend.core.config import get_settings


logger = logging.getLogger(__name__)

# Global singleton model
_minilm_model: Optional[SentenceTransformer] = None
_embedding_cache: dict[str, list[float]] = {}


def _get_minilm() -> SentenceTransformer:
    """
    Get or create MiniLM embedding model (lazy-loaded singleton).
    Reuses pattern from RV32I's pipeline.py lines 81-87.

    Returns:
        SentenceTransformer: MiniLM-L6-v2 model

    Raises:
        Exception: If model loading fails
    """
    global _minilm_model

    if _minilm_model is None:
        settings = get_settings()
        model_name = settings.EMBEDDING_MODEL

        try:
            logger.info(f"Loading embedding model: {model_name}")

            # Configure model cache
            os.environ["HF_HOME"] = settings.HF_HOME
            os.environ["TORCH_HOME"] = settings.TORCH_HOME

            # Detect device
            device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Using device: {device}")

            _minilm_model = SentenceTransformer(model_name, device=device)
            logger.info(f"Embedding model loaded successfully on {device}")

        except Exception as e:
            logger.error(f"Failed to load embedding model {model_name}: {e}")
            raise

    return _minilm_model


def embed_text(text: str, use_cache: bool = True) -> list[float]:
    """
    Encode text to embedding vector.
    Reuses pattern from RV32I's pipeline.py lines 99-107.

    Args:
        text: Text to embed
        use_cache: Whether to use cached embeddings

    Returns:
        list: 384-dimensional embedding vector (MiniLM output)
    """
    if not text:
        logger.warning("Empty text provided for embedding")
        return [0.0] * 384

    # Check cache
    if use_cache and text in _embedding_cache:
        logger.debug("Using cached embedding")
        return _embedding_cache[text]

    model = _get_minilm()

    try:
        # Encode with convert_to_numpy for consistency with RV32I
        embedding = model.encode(text, convert_to_numpy=True).tolist()

        # Cache result
        if use_cache:
            _embedding_cache[text] = embedding

        logger.debug(f"Embedded text of length {len(text)} to {len(embedding)}-dim vector")
        return embedding

    except Exception as e:
        logger.error(f"Failed to embed text: {e}")
        raise


def embed_security_event(event_dict: dict, use_cache: bool = False) -> list[float]:
    """
    Embed a structured security event.

    Concatenates key event fields (source_ip, action, severity, event_type) for embedding.

    Args:
        event_dict: Dictionary containing event fields
        use_cache: Whether to use cached embeddings

    Returns:
        list: Embedding vector
    """
    # Extract relevant fields for embedding
    parts = []

    if "event_type" in event_dict:
        parts.append(f"event_type: {event_dict['event_type']}")
    if "action" in event_dict:
        parts.append(f"action: {event_dict['action']}")
    if "severity" in event_dict:
        parts.append(f"severity: {event_dict['severity']}")
    if "source_ip" in event_dict:
        parts.append(f"source_ip: {event_dict['source_ip']}")
    if "target_resource" in event_dict:
        parts.append(f"target_resource: {event_dict['target_resource']}")
    if "source_user" in event_dict:
        parts.append(f"source_user: {event_dict['source_user']}")

    text = " | ".join(parts) if parts else "unknown event"
    return embed_text(text, use_cache=use_cache)


def embed_entity_context(
    entity_type: str,
    entity_name: str,
    entity_value: str,
    attributes: Optional[dict] = None,
) -> list[float]:
    """
    Embed entity context for graph node embeddings.

    Concatenates entity metadata (type, name, value, attributes) for embedding.

    Args:
        entity_type: Entity type ('IP', 'User', 'Host', 'File', 'Process', 'Domain', 'URL')
        entity_name: Human-readable entity name
        entity_value: Canonical entity value
        attributes: Optional entity metadata

    Returns:
        list: Embedding vector
    """
    parts = [f"type: {entity_type}", f"name: {entity_name}", f"value: {entity_value}"]

    if attributes:
        for key, value in attributes.items():
            if value is not None:
                parts.append(f"{key}: {value}")

    text = " | ".join(parts)
    return embed_text(text, use_cache=False)


def clear_cache() -> None:
    """Clear the embedding cache (useful for memory management)."""
    global _embedding_cache
    _embedding_cache.clear()
    logger.info("Embedding cache cleared")


def get_cache_stats() -> dict:
    """Get statistics about the embedding cache."""
    return {
        "cache_size": len(_embedding_cache),
        "model_loaded": _minilm_model is not None,
    }
