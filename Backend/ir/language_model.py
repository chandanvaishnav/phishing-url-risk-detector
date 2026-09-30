from collections import Counter
from functools import lru_cache
from math import exp, log
from typing import Iterable, Mapping

from Backend.ir.url_text import tokenize_url


PHISHING_LABELS = {"phishing", "high_risk"}
LEGITIMATE_LABELS = {"legitimate", "low_risk"}


def _classify_label(value: object) -> str | None:
    label = str(value or "").strip().lower()
    if label in PHISHING_LABELS:
        return "phishing"
    if label in LEGITIMATE_LABELS:
        return "legitimate"
    return None


@lru_cache(maxsize=4)
def _train_language_models(records: tuple[tuple[str, str], ...], smoothing: float):
    documents = {"phishing": [], "legitimate": []}
    vocabulary = set()
    for url, raw_label in records:
        label = _classify_label(raw_label)
        tokens = tokenize_url(url)
        if label and tokens:
            documents[label].append(tokens)
            vocabulary.update(tokens)

    class_counts = {
        label: Counter(token for document in class_documents for token in document)
        for label, class_documents in documents.items()
    }
    return documents, class_counts, vocabulary


def score_url_language_model(
    url: str,
    records: Iterable[Mapping[str, object]],
    smoothing: float = 1.0,
) -> dict:
    """Score URL tokens with class-conditional multinomial language models."""
    if smoothing <= 0:
        raise ValueError("smoothing must be greater than zero")

    record_key = tuple(
        (str(record.get("url") or ""), str(record.get("classification") or ""))
        for record in records
    )
    documents, class_counts, vocabulary = _train_language_models(record_key, float(smoothing))

    query_tokens = tokenize_url(url)
    vocabulary.update(query_tokens)
    if not query_tokens or not documents["phishing"] or not documents["legitimate"]:
        return {
            "status": "unavailable",
            "message": "Labeled phishing and legitimate URL history is required.",
            "score": None,
            "suspicious_terms": [],
            "training_documents": sum(map(len, documents.values())),
        }

    vocabulary_size = len(vocabulary) + 1
    total_documents = sum(map(len, documents.values()))
    token_totals = {label: sum(counts.values()) for label, counts in class_counts.items()}

    log_likelihoods = {}
    probabilities = {}
    for label in ("phishing", "legitimate"):
        class_documents = documents[label]
        prior = (len(class_documents) + smoothing) / (total_documents + 2 * smoothing)
        log_probability = log(prior)
        for token in query_tokens:
            probability = (class_counts[label][token] + smoothing) / (
                token_totals[label] + smoothing * vocabulary_size
            )
            log_probability += log(probability)
        log_likelihoods[label] = log_probability
        probabilities[label] = {
            token: (class_counts[label][token] + smoothing)
            / (token_totals[label] + smoothing * vocabulary_size)
            for token in set(query_tokens)
        }

    log_odds = log_likelihoods["phishing"] - log_likelihoods["legitimate"]
    if log_odds >= 0:
        score = 1.0 / (1.0 + exp(-min(log_odds, 700)))
    else:
        odds = exp(max(log_odds, -700))
        score = odds / (1.0 + odds)

    token_ratios = []
    for token in set(query_tokens):
        phishing_probability = probabilities["phishing"][token]
        legitimate_probability = probabilities["legitimate"][token]
        if phishing_probability > legitimate_probability:
            token_ratios.append((phishing_probability / legitimate_probability, token))

    suspicious_terms = [
        token for _, token in sorted(token_ratios, key=lambda item: (-item[0], item[1]))[:10]
    ]
    return {
        "status": "available",
        "score": round(score, 6),
        "suspicious_terms": suspicious_terms,
        "training_documents": total_documents,
    }
