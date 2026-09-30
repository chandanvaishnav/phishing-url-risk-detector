from Backend.ir.content_recommender import recommend_similar_urls
from Backend.ir import ir_service
from Backend.ir.language_model import score_url_language_model
from Backend.ir.pagerank import calculate_project_pagerank
from Backend.ir.url_text import tokenize_url


CORPUS = [
    {"url": "https://paypal-login.example/verify", "classification": "phishing"},
    {"url": "https://account-secure.example/signin", "classification": "phishing"},
    {"url": "https://library.example/catalog", "classification": "legitimate"},
    {"url": "https://news.example/article", "classification": "legitimate"},
]


def test_url_tokenizer_extracts_domain_and_path_terms():
    assert tokenize_url("https://paypal-login.example/verify-account") == [
        "paypal", "login", "example", "verify", "account"
    ]


def test_multinomial_language_model_uses_labeled_corpus_and_smoothing():
    result = score_url_language_model("https://paypal-login.example/verify", CORPUS)
    assert result["status"] == "available"
    assert 0 < result["score"] < 1
    assert "login" in result["suspicious_terms"]
    assert result["training_documents"] == 4


def test_project_pagerank_calculates_graph_rank():
    result = calculate_project_pagerank(
        "https://paypal-login.example/verify-account",
        [record["url"] for record in CORPUS],
    )
    assert result["status"] == "available"
    assert 0 < result["score"] <= 1
    assert 1 <= result["rank"] <= result["graph_nodes"]
    assert result["ranking_type"] == "project-level URL/domain graph ranking"


def test_project_pagerank_reports_insufficient_graph():
    result = calculate_project_pagerank("https://isolated.example", [])
    assert result["status"] == "unavailable"
    assert result["message"] == "Insufficient graph data."
    assert result["graph_nodes"] == 1
    assert result["graph_edges"] == 0


def test_tfidf_recommender_returns_only_corpus_urls():
    corpus_urls = [record["url"] for record in CORPUS]
    result = recommend_similar_urls("https://paypal-security.example/login", corpus_urls)
    recommendations = result["recommendations"]
    assert result["status"] == "available"
    assert recommendations
    assert all(item["url"] in corpus_urls for item in recommendations)
    assert all(0 < item["similarity"] <= 1 for item in recommendations)
    assert len(recommendations) <= 3


def test_tfidf_recommender_excludes_normalized_current_url():
    result = recommend_similar_urls(
        "https://same.example/",
        ["https://same.example", "https://same.example/"],
    )
    assert result["recommendations"] == []


def test_ir_service_keeps_other_components_when_one_fails(monkeypatch):
    records = (
        ("https://paypal-login.example/verify", "phishing"),
        ("https://library.example/catalog", "legitimate"),
    )
    monkeypatch.setattr(ir_service, "_database_signature", lambda: (2, 2))
    monkeypatch.setattr(ir_service, "_load_history", lambda signature: records)

    def fail_language_model(*args):
        raise RuntimeError("simulated language-model failure")

    monkeypatch.setattr(ir_service, "score_url_language_model", fail_language_model)
    result = ir_service.analyze_url_with_ir("https://paypal-login.example/account")

    assert result["language_model"]["status"] == "unavailable"
    assert result["pagerank"]["status"] == "available"
    assert result["content_recommendations"]["status"] == "available"
