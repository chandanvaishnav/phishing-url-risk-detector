import logging
import sqlite3
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from Backend.ir.content_recommender import recommend_similar_urls
from Backend.ir.language_model import score_url_language_model
from Backend.ir.pagerank import calculate_project_pagerank
from Backend.ir.url_text import normalize_url

logger = logging.getLogger("phishguard.ir")
DATABASE_PATH = Path(__file__).resolve().parents[2] / "db.sqlite3"


def _database_signature() -> tuple[int, int]:
    try:
        with sqlite3.connect(f"file:{DATABASE_PATH.as_posix()}?mode=ro", uri=True, timeout=1) as connection:
            row = connection.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM scan_history").fetchone()
        return int(row[0]), int(row[1])
    except sqlite3.Error:
        logger.exception("Could not inspect scan history for IR corpus")
        return 0, 0


@lru_cache(maxsize=4)
def _load_history(signature: tuple[int, int]) -> tuple[tuple[str, str], ...]:
    del signature
    try:
        with sqlite3.connect(f"file:{DATABASE_PATH.as_posix()}?mode=ro", uri=True, timeout=1) as connection:
            rows = connection.execute(
                "SELECT url, classification FROM scan_history ORDER BY id"
            ).fetchall()
        records = []
        for raw_url, classification in rows:
            normalized = normalize_url(raw_url)
            hostname = urlsplit(normalized).hostname or ""
            if normalized and "." in hostname:
                records.append((normalized, str(classification or "")))
        return tuple(records)
    except sqlite3.Error:
        logger.exception("Could not load scan history for IR corpus")
        return ()


def analyze_url_with_ir(url: str) -> dict:
    """Run local IR analyses over actual, labeled project scan history."""
    signature = _database_signature()
    records = _load_history(signature)
    corpus_urls = tuple(sorted({record_url for record_url, _ in records}))
    record_mappings = tuple(
        {"url": record_url, "classification": label}
        for record_url, label in records
    )

    analyses = {}
    components = (
        ("language_model", lambda: score_url_language_model(url, record_mappings)),
        ("pagerank", lambda: calculate_project_pagerank(url, corpus_urls)),
        ("content_recommendations", lambda: recommend_similar_urls(url, corpus_urls)),
    )
    for name, analyze in components:
        try:
            analyses[name] = analyze()
        except Exception:
            logger.exception("IR component %s failed", name)
            analyses[name] = {
                "status": "unavailable",
                "message": "IR analysis temporarily unavailable",
            }

    available = any(component.get("status") == "available" for component in analyses.values())
    result = {
        "status": "available" if available else "unavailable",
        "corpus_size": len(corpus_urls),
        **analyses,
    }
    if not available:
        result["message"] = "IR analysis requires usable scan history."
    return result
