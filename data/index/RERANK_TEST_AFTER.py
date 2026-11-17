def test_reranker_fallback_is_recorded(monkeypatch):
    local = replace(
        settings,
        rerank_model="primary",
        rerank_revision="primary-revision",
        rerank_fallback_model="fallback",
        rerank_fallback_revision="fallback-revision",
    )
    monkeypatch.setattr(models, "settings", local)
    models.reranker_model.cache_clear()
    loaded = []

    def loader(name, revision, device):
        loaded.append(name)
        if name == "primary":
            raise models.ModelLoadError("broken")
        return type("FakeReranker", (), {"predict": lambda self, pairs: [0.5 for _ in pairs]})()

    monkeypatch.setattr(models, "reranker_model", loader)
    models.RERANK_FALLBACK_USED = False
    models.RERANKER_USED_MODEL = ""
    scores = models.rerank("q", ["text", "other"])
    assert loaded == ["primary", "fallback"]
    assert np.array_equal(scores, np.array([0.5, 0.5], dtype=np.float32))
    assert models.RERANK_FALLBACK_USED
    assert models.RERANKER_USED_MODEL == "fallback"
    manifest = models.reranker_manifest()
    assert manifest["reranker_model_requested"] == "primary"
    assert manifest["reranker_model_used"] == "fallback"
    assert manifest["reranker_revision_used"] == "fallback-revision"
    assert manifest["fallback_used"] is True
    assert manifest["fallback_reason"] == "broken"


def test_reranker_fails_without_scores_when_primary_and_fallback_fail(monkeypatch):
    local = replace(
        settings,
        rerank_model="primary",
        rerank_revision="primary-revision",
        rerank_fallback_model="fallback",
        rerank_fallback_revision="fallback-revision",
    )
    monkeypatch.setattr(models, "settings", local)
    loaded = []

    def loader(name, revision, device):
        loaded.append((name, revision))
        raise models.ModelLoadError("broken")

    monkeypatch.setattr(models, "reranker_model", loader)
    with pytest.raises(models.ModelLoadError, match="fallback reranker failed"):
        models.rerank("q", ["text"])
    assert loaded == [
        ("primary", "primary-revision"),
        ("fallback", "fallback-revision"),
    ]


def test_real_configured_primary_reranker() -> None:
    snapshot = Path(HF_HUB_CACHE) / "models--BAAI--bge-reranker-v2-m3" / "snapshots" / settings.rerank_revision
    if not snapshot.is_dir():
        pytest.skip(f"configured primary model files are not local: {snapshot}")
    scores = models.rerank("security issue", ["security issue", "unrelated text"])
    assert len(scores) == 2
    assert np.isfinite(scores).all()
    manifest = models.reranker_manifest()
    assert manifest["reranker_model_used"] == settings.rerank_model
    assert manifest["reranker_revision_used"] == settings.rerank_revision
    assert manifest["fallback_used"] is False


