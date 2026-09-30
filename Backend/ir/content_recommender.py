from functools import lru_cache
from typing import Iterable

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from Backend.ir.url_text import normalize_url, tokenize_url


def _token_analyzer(value: str) -> list[str]:
    return tokenize_url(value)


@lru_cache(maxsize=8)
def _build_url_index(urls: tuple[str, ...]):
    if not urls:
        return None, None
    vectorizer = TfidfVectorizer(
        tokenizer=_token_analyzer,
        token_pattern=None,
        lowercase=False,
        ngram_range=(1, 2),
    )
    matrix = vectorizer.fit_transform(urls)
    return vectorizer, matrix


def recommend_similar_urls(url: str, corpus_urls: Iterable[str], limit: int = 3) -> dict:
    """Return nearest historical URLs using TF-IDF cosine similarity."""
    if limit < 1:
        raise ValueError("limit must be positive")
    target = normalize_url(url)
    indexed = {}
    for item in corpus_urls:
        normalized = normalize_url(item)
        if normalized and normalized != target:
            indexed.setdefault(normalized, item)
    urls = tuple(sorted(indexed))
    if not target or not urls:
        return {"status": "available", "recommendations": []}

    try:
        vectorizer, matrix = _build_url_index(urls)
        query_vector = vectorizer.transform([target])
        similarities = (matrix @ query_vector.T).toarray().ravel()
    except ValueError:
        return {"status": "available", "recommendations": []}

    order = np.argsort(-similarities)
    recommendations = []
    for index in order:
        similarity = float(similarities[index])
        if similarity <= 0:
            continue
        recommendations.append({
            "url": indexed[urls[index]],
            "similarity": round(similarity, 6),
        })
        if len(recommendations) >= limit:
            break
    return {"status": "available", "recommendations": recommendations}
