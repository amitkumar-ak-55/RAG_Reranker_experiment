from reranker_experiment.metrics import aggregate, ndcg_at_k, precision_at_k, recall_at_k, reciprocal_rank


def test_metrics_are_deterministic():
    ranked = ["a", "b", "c"]
    gold = {"b"}
    assert recall_at_k(ranked, gold, 5) == 1.0
    assert precision_at_k(ranked, gold, 5) == 0.2
    assert reciprocal_rank(ranked, gold) == 0.5
    assert ndcg_at_k(ranked, gold, 5) == 1 / 1.584962500721156


def test_aggregate_excludes_failed_requests_from_means():
    rows = [
        {"error": "", "recall_at_5": 1, "precision_at_5": 0.2, "mrr": 1, "ndcg_at_5": 1, "latency_ms": 10},
        {"error": "failed", "recall_at_5": 0, "precision_at_5": 0, "mrr": 0, "ndcg_at_5": 0, "latency_ms": 20},
    ]
    assert aggregate(rows) == {
        "questions": 2,
        "successful": 1,
        "failed": 1,
        "mean_recall_at_5": 1.0,
        "mean_precision_at_5": 0.2,
        "mean_mrr": 1.0,
        "mean_ndcg_at_5": 1.0,
        "mean_latency_ms": 10.0,
    }

