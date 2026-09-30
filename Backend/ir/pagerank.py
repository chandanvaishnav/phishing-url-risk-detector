from collections.abc import Iterable
from functools import lru_cache

from Backend.ir.url_text import normalize_url, tokenize_url


GENERIC_TOKENS = {"com", "org", "net", "edu", "gov", "www", "http", "https"}


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or ""


def _related(first_url: str, second_url: str) -> bool:
    first_host = _host(first_url)
    second_host = _host(second_url)
    if first_host == second_host or first_host.endswith("." + second_host) or second_host.endswith("." + first_host):
        return True

    first_tokens = set(tokenize_url(first_url)) - GENERIC_TOKENS
    second_tokens = set(tokenize_url(second_url)) - GENERIC_TOKENS
    union = first_tokens | second_tokens
    similarity = len(first_tokens & second_tokens) / len(union) if union else 0.0
    return similarity >= 0.25


def calculate_project_pagerank(
    url: str,
    corpus_urls: Iterable[str],
    damping: float = 0.85,
    max_iterations: int = 100,
    tolerance: float = 1e-10,
) -> dict:
    return _calculate_project_pagerank_cached(
        url,
        tuple(corpus_urls),
        damping,
        max_iterations,
        tolerance,
    )


@lru_cache(maxsize=128)
def _calculate_project_pagerank_cached(
    url: str,
    corpus_urls: tuple[str, ...],
    damping: float,
    max_iterations: int,
    tolerance: float,
) -> dict:
    """Rank a URL in a project graph of URL/domain relationships, not the live web."""
    if not 0 < damping < 1:
        raise ValueError("damping must be between zero and one")
    target = normalize_url(url)
    nodes = sorted({normalized for item in corpus_urls if (normalized := normalize_url(item))} | ({target} if target else set()))
    if not target or not nodes:
        return {"status": "unavailable", "message": "No valid URL graph is available."}

    adjacency = {node: {} for node in nodes}
    for index, first in enumerate(nodes):
        for second in nodes[index + 1 :]:
            if _related(first, second):
                adjacency[first][second] = 1.0
                adjacency[second][first] = 1.0

    node_count = len(nodes)
    edge_count = sum(len(links) for links in adjacency.values()) // 2
    if node_count < 2 or edge_count == 0:
        return {
            "status": "unavailable",
            "message": "Insufficient graph data.",
            "score": None,
            "rank": None,
            "graph_nodes": node_count,
            "graph_edges": edge_count,
            "ranking_type": "project-level URL/domain graph ranking",
        }

    ranks = {node: 1.0 / node_count for node in nodes}
    for _ in range(max_iterations):
        dangling_mass = sum(ranks[node] for node in nodes if not adjacency[node])
        next_ranks = {
            node: (1.0 - damping) / node_count + damping * dangling_mass / node_count
            for node in nodes
        }
        for source, links in adjacency.items():
            if not links:
                continue
            total_weight = sum(links.values())
            for destination, weight in links.items():
                next_ranks[destination] += damping * ranks[source] * weight / total_weight
        difference = sum(abs(next_ranks[node] - ranks[node]) for node in nodes)
        ranks = next_ranks
        if difference < tolerance:
            break

    ordered_nodes = sorted(nodes, key=lambda node: (-ranks[node], node))
    return {
        "status": "available",
        "score": round(ranks[target], 8),
        "rank": ordered_nodes.index(target) + 1,
        "graph_nodes": node_count,
        "graph_edges": edge_count,
        "ranking_type": "project-level URL/domain graph ranking",
    }
