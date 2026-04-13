"""
Retriever module for Argus XDR.
Implements hybrid search combining topological graph queries, semantic search, and keyword search.
Reuses RRF and cross-encoder patterns from RV32I project.
"""

import logging
from typing import Optional

try:
    from rank_bm25 import BM25Okapi
    from sentence_transformers import CrossEncoder
    import numpy as np
except ImportError:
    raise ImportError(
        "Required libraries missing. Install with: "
        "pip install rank_bm25 sentence-transformers numpy"
    )

from backend.core.database import (
    query_nodes,
    semantic_search,
    query_knowledge,
    get_connected_nodes,
)
from backend.rag.embedder import embed_text
from backend.core.config import get_settings


logger = logging.getLogger(__name__)

# Global singleton reranker model
_reranker_model: Optional[CrossEncoder] = None


def _get_reranker() -> CrossEncoder:
    """
    Get or create cross-encoder reranker model (lazy-loaded singleton).

    Returns:
        CrossEncoder: Cross-encoder model for reranking
    """
    global _reranker_model

    if _reranker_model is None:
        settings = get_settings()
        model_name = settings.RERANKER_MODEL

        try:
            logger.info(f"Loading reranker model: {model_name}")
            _reranker_model = CrossEncoder(model_name)
            logger.info("Reranker model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load reranker model {model_name}: {e}")
            raise

    return _reranker_model


def _bm25_search(
    corpus_docs: list[str],
    corpus_ids: list[str],
    query: str,
    k: int = 5,
) -> list[str]:
    """
    Perform BM25 keyword search.
    Reuses pattern from RV32I's pipeline.py lines 140-156.

    Args:
        corpus_docs: List of documents to search
        corpus_ids: List of document IDs corresponding to corpus_docs
        query: Search query
        k: Number of top results to return

    Returns:
        list: Top k document IDs sorted by BM25 score
    """
    if not corpus_docs or not corpus_ids:
        return []

    try:
        # Tokenize
        tokenized_corpus = [doc.lower().split() for doc in corpus_docs]
        tokenized_query = query.lower().split()

        # Create BM25 index
        bm25 = BM25Okapi(tokenized_corpus)
        scores = bm25.get_scores(tokenized_query)

        # Rank and return top k
        ranked = sorted(
            zip(corpus_ids, scores),
            key=lambda x: x[1],
            reverse=True,
        )
        return [doc_id for doc_id, _ in ranked[:k]]

    except Exception as e:
        logger.warning(f"BM25 search failed: {e}")
        return []


def _reciprocal_rank_fusion(
    semantic_ids: list[str],
    bm25_ids: list[str],
    k: int = 60,
) -> list[str]:
    """
    Combine search results using Reciprocal Rank Fusion (RRF).
    Reuses pattern from RV32I's pipeline.py lines 158-173.

    Args:
        semantic_ids: List of document IDs from semantic search (ordered by relevance)
        bm25_ids: List of document IDs from BM25 search (ordered by score)
        k: RRF parameter (default 60)

    Returns:
        list: Combined ranked list of document IDs
    """
    scores = {}

    # Add semantic search scores
    for rank, doc_id in enumerate(semantic_ids, start=1):
        scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)

    # Add BM25 scores
    for rank, doc_id in enumerate(bm25_ids, start=1):
        scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)

    # Sort by combined score
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [doc_id for doc_id, _ in ranked]


def _cross_encode_rerank(
    query: str,
    candidates: list[dict],
    k: int = 5,
) -> list[dict]:
    """
    Rerank search results using cross-encoder model.

    Args:
        query: Original query string
        candidates: List of candidate result dictionaries
        k: Number of top results to keep

    Returns:
        list: Top k candidates reranked by cross-encoder
    """
    if not candidates:
        return []

    settings = get_settings()
    if not settings.ENABLE_RERANKING:
        return candidates[:k]

    try:
        model = _get_reranker()

        # Prepare pairs for cross-encoder
        pairs = [[query, cand.get("content", "")] for cand in candidates]

        # Score pairs
        scores = model.predict(pairs)

        # Combine candidates with scores
        scored_candidates = [
            (cand, score) for cand, score in zip(candidates, scores)
        ]

        # Sort by score descending
        scored_candidates.sort(key=lambda x: x[1], reverse=True)

        # Return top k
        return [cand for cand, _ in scored_candidates[:k]]

    except Exception as e:
        logger.warning(f"Cross-encoder reranking failed, returning original order: {e}")
        return candidates[:k]


def retrieve_threat_context(
    query: str,
    k: int = 5,
    include_topological: bool = True,
) -> list[dict]:
    """
    Main hybrid retrieval function combining topological and semantic search.

    Implements the 5-step retrieval process:
    1. SQL topological fetch (connected nodes/edges)
    2. Semantic search via pgvector
    3. BM25 keyword search
    4. RRF merge
    5. Cross-encoder reranking

    Args:
        query: Natural language query or question
        k: Number of top results to return
        include_topological: Whether to include topological search

    Returns:
        list: Top k relevant results as dictionaries
    """
    settings = get_settings()
    results_by_id = {}

    try:
        # Step 1: Topological search (if enabled)
        if include_topological and settings.ENABLE_HYBRID_SEARCH:
            logger.debug("Performing topological search...")
            # Query recent critical logs
            all_nodes = query_nodes(limit=100)
            for node in all_nodes:
                # Get connected nodes (neighbors)
                try:
                    neighbors = get_connected_nodes(node["id"])
                    results_by_id[node["id"]] = {
                        "id": node["id"],
                        "type": "node",
                        "entity_type": node["entity_type"],
                        "name": node["name"],
                        "value": node["value"],
                        "neighbors_count": len(neighbors),
                        "score": 0.0,
                        "source": "topological",
                    }
                except Exception as e:
                    logger.debug(f"Could not fetch neighbors for node {node['id']}: {e}")

        # Step 2: Semantic search via pgvector
        logger.debug("Performing semantic search...")
        query_embedding = embed_text(query)

        try:
            semantic_results = semantic_search(query_embedding, limit=k * 3)
            semantic_ids = [r["id"] for r in semantic_results]

            for i, result in enumerate(semantic_results):
                result_id = result["id"]
                if result_id not in results_by_id:
                    results_by_id[result_id] = {
                        "id": result_id,
                        "type": "embedding",
                        "content": result.get("content", ""),
                        "score": 0.0,
                        "source": "semantic",
                    }
                results_by_id[result_id]["semantic_rank"] = i + 1
        except Exception as e:
            logger.warning(f"Semantic search failed: {e}")
            semantic_ids = []

        # Step 3: BM25 keyword search
        logger.debug("Performing BM25 keyword search...")
        try:
            # Get all log contents for BM25
            all_embeddings = query_knowledge(limit=100)
            log_contents = [e.get("content", "") for e in all_embeddings]
            log_ids = [e["id"] for e in all_embeddings]

            bm25_ids = _bm25_search(log_contents, log_ids, query, k=k * 3)

            for i, result_id in enumerate(bm25_ids):
                if result_id not in results_by_id:
                    results_by_id[result_id] = {
                        "id": result_id,
                        "type": "knowledge",
                        "score": 0.0,
                        "source": "bm25",
                    }
                results_by_id[result_id]["bm25_rank"] = i + 1
        except Exception as e:
            logger.warning(f"BM25 search failed: {e}")
            bm25_ids = []

        # Step 4: RRF merge
        logger.debug("Merging results with RRF...")
        merged_ids = _reciprocal_rank_fusion(semantic_ids, bm25_ids)

        # Reorder results by merged ranking
        final_results = []
        for i, result_id in enumerate(merged_ids):
            if result_id in results_by_id:
                result = results_by_id[result_id]
                result["final_rank"] = i + 1
                final_results.append(result)

        # Add remaining results not in merged list
        for result_id, result in results_by_id.items():
            if not any(r["id"] == result_id for r in final_results):
                result["final_rank"] = len(final_results) + 1
                final_results.append(result)

        # Step 5: Cross-encoder reranking
        if settings.ENABLE_RERANKING and final_results:
            logger.debug("Applying cross-encoder reranking...")
            final_results = _cross_encode_rerank(query, final_results, k=k)

        # Truncate to k results
        final_results = final_results[:k]

        logger.info(f"Retrieved {len(final_results)} threat context results")
        return final_results

    except Exception as e:
        logger.error(f"Threat context retrieval failed: {e}")
        return []


def query_security_knowledge(
    query: str,
    category_filter: Optional[str] = None,
    k: int = 5,
) -> list[dict]:
    """
    Query the security knowledge base by category and semantic similarity.

    Args:
        query: Query string or question
        category_filter: Filter by category ('attack_pattern', 'detection_rule', 'mitigation_strategy')
        k: Number of top results to return

    Returns:
        list: List of relevant knowledge entries
    """
    try:
        # Get knowledge entries by category
        knowledge_entries = query_knowledge(category=category_filter, limit=100)

        if not knowledge_entries:
            logger.warning(f"No knowledge entries found for category: {category_filter}")
            return []

        # Semantic search within knowledge base
        query_embedding = embed_text(query)

        # Score by semantic similarity
        scores = {}
        for entry in knowledge_entries:
            if entry.get("embedding"):
                entry_vec = np.array(entry["embedding"])
                query_vec = np.array(query_embedding)

                # Cosine similarity
                similarity = np.dot(query_vec, entry_vec) / (
                    np.linalg.norm(query_vec) * np.linalg.norm(entry_vec) + 1e-8
                )
                scores[entry["id"]] = similarity

        # Sort by similarity
        sorted_entries = sorted(
            knowledge_entries,
            key=lambda x: scores.get(x["id"], 0.0),
            reverse=True,
        )

        return sorted_entries[:k]

    except Exception as e:
        logger.error(f"Knowledge base query failed: {e}")
        return []
