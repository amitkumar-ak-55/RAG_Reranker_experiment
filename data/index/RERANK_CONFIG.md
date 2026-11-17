# Reranker configuration verification

## `.env` lines

```text
RERANK_MODEL=BAAI/bge-reranker-v2-m3
RERANK_REVISION=953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e
RERANK_DEVICE=cpu
RERANK_FALLBACK_MODEL=BAAI/bge-reranker-base
RERANK_FALLBACK_REVISION=2cfc18c9415c912f9d8155881c133215df768a70
```

Revisions were resolved at runtime from the Hugging Face API.

## Download output

```text
model: BAAI/bge-base-en-v1.5 path=C:\Users\bhagy\.cache\huggingface\hub\models--BAAI--bge-base-en-v1.5\snapshots\a5beb1e3e68b9ab74eb54cfd186867f64f240e1a
revision: a5beb1e3e68b9ab74eb54cfd186867f64f240e1a
model: BAAI/bge-reranker-v2-m3 path=C:\Users\bhagy\.cache\huggingface\hub\models--BAAI--bge-reranker-v2-m3\snapshots\953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e
revision: 953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e
model: BAAI/bge-reranker-base path=C:\Users\bhagy\.cache\huggingface\hub\models--BAAI--bge-reranker-base\snapshots\2cfc18c9415c912f9d8155881c133215df768a70
revision: 2cfc18c9415c912f9d8155881c133215df768a70
```

## Real primary sample

```text
scores: [0.9992109537124634, 0.00013459329784382135]
finite: True
reranker_model_requested: BAAI/bge-reranker-v2-m3
reranker_model_used: BAAI/bge-reranker-v2-m3
reranker_revision_used: 953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e
fallback_used: False
fallback_reason: None
```

The primary loaded successfully on CPU, so the fallback was not used. No
corpus rebuild or retrieval evaluation was run.

## `RERANK_TEST_DIFF.txt`

```diff
diff --git a/data/index/RERANK_TEST_BEFORE.py b/data/index/RERANK_TEST_AFTER.py
index 18c5f70..853f965 100644
--- a/data/index/RERANK_TEST_BEFORE.py
+++ b/data/index/RERANK_TEST_AFTER.py
@@ -29,6 +29,7 @@
     assert manifest["reranker_model_used"] == "fallback"
     assert manifest["reranker_revision_used"] == "fallback-revision"
     assert manifest["fallback_used"] is True
+    assert manifest["fallback_reason"] == "broken"
 
 
 def test_reranker_fails_without_scores_when_primary_and_fallback_fail(monkeypatch):
@@ -55,3 +56,16 @@ def test_reranker_fails_without_scores_when_primary_and_fallback_fail(monkeypatc
     ]
 
 
+def test_real_configured_primary_reranker() -> None:
+    snapshot = Path(HF_HUB_CACHE) / "models--BAAI--bge-reranker-v2-m3" / "snapshots" / settings.rerank_revision
+    if not snapshot.is_dir():
+        pytest.skip(f"configured primary model files are not local: {snapshot}")
+    scores = models.rerank("security issue", ["security issue", "unrelated text"])
+    assert len(scores) == 2
+    assert np.isfinite(scores).all()
+    manifest = models.reranker_manifest()
+    assert manifest["reranker_model_used"] == settings.rerank_model
+    assert manifest["reranker_revision_used"] == settings.rerank_revision
+    assert manifest["fallback_used"] is False
+
+

```

## Full pytest -v output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\bhagy\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\bhagy\Desktop\CysekRAG
configfile: pytest.ini
plugins: anyio-4.13.0
collecting ... collected 65 items

tests/test_arm_e.py::test_arm_e_ranks_scores_and_breaks_ties_by_bm25_rank PASSED [  1%]
tests/test_arm_e.py::test_candidate_cap_sets_flag PASSED                 [  3%]
tests/test_arm_e.py::test_precision_at_k_handles_fewer_gold_items PASSED [  4%]
tests/test_arm_e.py::test_arm_e_is_not_configured_without_jev PASSED     [  6%]
tests/test_arm_e.py::test_jev_scoring_uses_choice_and_noul_schema PASSED [  7%]
tests/test_authorization.py::test_scan_requires_authorization PASSED     [  9%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.1] PASSED [ 10%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[example.test] PASSED [ 12%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/24] PASSED [ 13%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/32] PASSED [ 15%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[10.0.0.0/8] PASSED [ 16%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[not a host!] PASSED [ 18%]
tests/test_authorization.py::test_scan_job_stores_authorization_and_metadata PASSED [ 20%]
tests/test_cli.py::test_scan_requires_authorized PASSED                  [ 21%]
tests/test_cli.py::test_scan_rejects_invalid_target PASSED               [ 23%]
tests/test_cli.py::test_scanme_rejects_nuclei PASSED                     [ 24%]
tests/test_cli.py::test_check_jev_exit_codes PASSED                      [ 26%]
tests/test_kb_build.py::test_every_record_has_exactly_the_19_keys PASSED [ 27%]
tests/test_kb_build.py::test_text_is_byte_identical_to_fixture_input PASSED [ 29%]
tests/test_kb_build.py::test_distractor_sharing_cwe_is_admitted_with_rule_cwe PASSED [ 30%]
tests/test_kb_build.py::test_distractor_sharing_only_vendor_is_rejected PASSED [ 32%]
tests/test_kb_build.py::test_distractor_sharing_vendor_product_is_admitted_with_rule_vendor_product PASSED [ 33%]
tests/test_kb_build.py::test_distractor_sharing_both_records_cwe_first_and_also PASSED [ 35%]
tests/test_kb_build.py::test_kev_distractor_is_rejected PASSED           [ 36%]
tests/test_kb_build.py::test_attack_id_missing_from_bundle_is_skipped PASSED [ 38%]
tests/test_kb_build.py::test_revoked_attack_technique_is_skipped PASSED  [ 40%]
tests/test_kb_build.py::test_valid_attack_technique_builds_correct_record PASSED [ 41%]
tests/test_kb_build.py::test_cwe_referenced_by_target_and_distractor_appears_once_with_group_positive PASSED [ 43%]
tests/test_kb_build.py::test_targets_total_equals_positive_cves_plus_kev_cves PASSED [ 44%]
tests/test_kb_build.py::test_nuclei_published_and_last_modified_are_null PASSED [ 46%]
tests/test_kb_build.py::test_every_skipped_reason_is_in_the_allowed_list PASSED [ 47%]
tests/test_metrics.py::test_claim_metrics PASSED                         [ 49%]
tests/test_parsers.py::test_nmap_parser PASSED                           [ 50%]
tests/test_parsers.py::test_nuclei_parser PASSED                         [ 52%]
tests/test_queue.py::test_queue_runs_one_at_a_time_and_cancel PASSED     [ 53%]
tests/test_regressions.py::test_local_models_produce_embeddings_without_openrouter PASSED [ 55%]
tests/test_regressions.py::test_semantic_embedding_retrieves_paraphrase PASSED [ 56%]
tests/test_regressions.py::test_jev_clean_skip PASSED                    [ 58%]
tests/test_regressions.py::test_jev_uses_system_one_api PASSED           [ 60%]
tests/test_regressions.py::test_jev_health_success PASSED                [ 61%]
tests/test_regressions.py::test_jev_health_auth_failure PASSED           [ 63%]
tests/test_regressions.py::test_jev_health_model_or_endpoint_failure PASSED [ 64%]
tests/test_regressions.py::test_jev_health_timeout_and_connection_refused PASSED [ 66%]
tests/test_regressions.py::test_jev_health_blank_config PASSED           [ 67%]
tests/test_regressions.py::test_jev_url_checker_reports_endpoint_path PASSED [ 69%]
tests/test_regressions.py::test_cache_changes_with_model PASSED          [ 70%]
tests/test_regressions.py::test_cost_unknown_when_prices_blank PASSED    [ 72%]
tests/test_retrieval.py::test_retrieval_arms PASSED                      [ 73%]
tests/test_retrieval_upgrade.py::test_chunker_keeps_short_documents_whole_and_metadata PASSED [ 75%]
tests/test_retrieval_upgrade.py::test_chunker_splits_on_sentences_with_fifty_token_overlap PASSED [ 76%]
tests/test_retrieval_upgrade.py::test_index_version_changes_only_for_index_inputs PASSED [ 78%]
tests/test_retrieval_upgrade.py::test_embedding_cache_makes_zero_calls_for_unchanged_chunks PASSED [ 80%]
tests/test_retrieval_upgrade.py::test_tokenizer_keeps_cve_and_cwe_ids_whole PASSED [ 81%]
tests/test_retrieval_upgrade.py::test_rrf_matches_hand_computed_k60 PASSED [ 83%]
tests/test_retrieval_upgrade.py::test_metadata_filter_is_applied_before_every_stage PASSED [ 84%]
tests/test_retrieval_upgrade.py::test_reranker_fallback_is_recorded PASSED [ 86%]
tests/test_retrieval_upgrade.py::test_reranker_fails_without_scores_when_primary_and_fallback_fail PASSED [ 87%]
tests/test_retrieval_upgrade.py::test_real_configured_primary_reranker PASSED [ 89%]
tests/test_retrieval_upgrade.py::test_arm_2_path_never_calls_sparse_or_reranker PASSED [ 90%]
tests/test_retrieval_upgrade.py::test_eval_metrics_hand_computed_fixture PASSED [ 92%]
tests/test_retrieval_upgrade.py::test_bootstrap_ci_is_reproducible PASSED [ 93%]
tests/test_scanme.py::test_scanme_resolves_without_target_restriction PASSED [ 95%]
tests/test_scanme.py::test_scanme_nuclei_is_not_invoked PASSED           [ 96%]
tests/test_scanme.py::test_scanme_nmap_command_is_low_rate_and_not_aggressive PASSED [ 98%]
tests/test_wait.py::test_port_wait_timeout PASSED                        [100%]

======================== 65 passed in 70.88s (0:01:10) ========================

```
