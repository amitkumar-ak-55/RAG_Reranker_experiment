# Reranker fallback fix

## Root cause and changed line

The failing implementation was in
`rag_verify_lab/models.py` at the fallback selection line that previously
loaded only `settings.rerank_model`:

```python
model = reranker_model(settings.rerank_model, settings.rerank_revision, settings.rerank_device)
```

It now tries the requested primary first and, only when that load raises
`ModelLoadError`, loads `settings.rerank_fallback_model` with
`settings.rerank_fallback_revision`. A failure of both models raises
`ModelLoadError` and produces no scores.

## Added `.env` lines

```text
RERANK_FALLBACK_MODEL=BAAI/bge-reranker-base
RERANK_FALLBACK_REVISION=2cfc18c9415c912f9d8155881c133215df768a70
```

The same fallback model and blank revision were added to `.env.example`.
The revision was resolved at runtime from the Hugging Face API:

```text
2cfc18c9415c912f9d8155881c133215df768a70
```

Manifests now record `reranker_model_requested`, `reranker_model_used`,
`reranker_revision_used`, and `fallback_used`.

## Test results

Targeted command:

```text
pytest tests/test_retrieval_upgrade.py -v
```

Result: **12 passed**.

Full command and complete output:

```text
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\bhagy\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\bhagy\Desktop\CysekRAG
configfile: pytest.ini
plugins: anyio-4.13.0
collecting ... collected 64 items

tests/test_arm_e.py::test_arm_e_ranks_scores_and_breaks_ties_by_bm25_rank PASSED [  1%]
tests/test_arm_e.py::test_candidate_cap_sets_flag PASSED                 [  3%]
tests/test_arm_e.py::test_precision_at_k_handles_fewer_gold_items PASSED [  4%]
tests/test_arm_e.py::test_arm_e_is_not_configured_without_jev PASSED     [  6%]
tests/test_arm_e.py::test_jev_scoring_uses_choice_and_noul_schema PASSED [  7%]
tests/test_authorization.py::test_scan_requires_authorization PASSED     [  9%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.1] PASSED [ 10%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[example.test] PASSED [ 12%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/24] PASSED [ 14%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/32] PASSED [ 15%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[10.0.0.0/8] PASSED [ 17%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[not a host!] PASSED [ 18%]
tests/test_authorization.py::test_scan_job_stores_authorization_and_metadata PASSED [ 20%]
tests/test_cli.py::test_scan_requires_authorized PASSED                  [ 21%]
tests/test_cli.py::test_scan_rejects_invalid_target PASSED               [ 23%]
tests/test_cli.py::test_scanme_rejects_nuclei PASSED                     [ 25%]
tests/test_cli.py::test_check_jev_exit_codes PASSED                      [ 26%]
tests/test_kb_build.py::test_every_record_has_exactly_the_19_keys PASSED [ 28%]
tests/test_kb_build.py::test_text_is_byte_identical_to_fixture_input PASSED [ 29%]
tests/test_kb_build.py::test_distractor_sharing_cwe_is_admitted_with_rule_cwe PASSED [ 31%]
tests/test_kb_build.py::test_distractor_sharing_only_vendor_is_rejected PASSED [ 32%]
tests/test_kb_build.py::test_distractor_sharing_vendor_product_is_admitted_with_rule_vendor_product PASSED [ 34%]
tests/test_kb_build.py::test_distractor_sharing_both_records_cwe_first_and_also PASSED [ 35%]
tests/test_kb_build.py::test_kev_distractor_is_rejected PASSED           [ 37%]
tests/test_kb_build.py::test_attack_id_missing_from_bundle_is_skipped PASSED [ 39%]
tests/test_kb_build.py::test_revoked_attack_technique_is_skipped PASSED  [ 40%]
tests/test_kb_build.py::test_valid_attack_technique_builds_correct_record PASSED [ 42%]
tests/test_kb_build.py::test_cwe_referenced_by_target_and_distractor_appears_once_with_group_positive PASSED [ 43%]
tests/test_kb_build.py::test_targets_total_equals_positive_cves_plus_kev_cves PASSED [ 45%]
tests/test_kb_build.py::test_nuclei_published_and_last_modified_are_null PASSED [ 46%]
tests/test_kb_build.py::test_every_skipped_reason_is_in_the_allowed_list PASSED [ 48%]
tests/test_metrics.py::test_claim_metrics PASSED                         [ 50%]
tests/test_parsers.py::test_nmap_parser PASSED                           [ 51%]
tests/test_parsers.py::test_nuclei_parser PASSED                         [ 53%]
tests/test_queue.py::test_queue_runs_one_at_a_time_and_cancel PASSED     [ 54%]
tests/test_regressions.py::test_local_models_produce_embeddings_without_openrouter PASSED [ 56%]
tests/test_regressions.py::test_semantic_embedding_retrieves_paraphrase PASSED [ 57%]
tests/test_regressions.py::test_jev_clean_skip PASSED                    [ 59%]
tests/test_regressions.py::test_jev_uses_system_one_api PASSED           [ 60%]
tests/test_regressions.py::test_jev_health_success PASSED                [ 62%]
tests/test_regressions.py::test_jev_health_auth_failure PASSED           [ 64%]
tests/test_regressions.py::test_jev_health_model_or_endpoint_failure PASSED [ 65%]
tests/test_regressions.py::test_jev_health_timeout_and_connection_refused PASSED [ 67%]
tests/test_regressions.py::test_jev_health_blank_config PASSED           [ 68%]
tests/test_regressions.py::test_jev_url_checker_reports_endpoint_path PASSED [ 70%]
tests/test_regressions.py::test_cache_changes_with_model PASSED          [ 71%]
tests/test_regressions.py::test_cost_unknown_when_prices_blank PASSED    [ 73%]
tests/test_retrieval.py::test_retrieval_arms PASSED                      [ 75%]
tests/test_retrieval_upgrade.py::test_chunker_keeps_short_documents_whole_and_metadata PASSED [ 76%]
tests/test_retrieval_upgrade.py::test_chunker_splits_on_sentences_with_fifty_token_overlap PASSED [ 78%]
tests/test_retrieval_upgrade.py::test_index_version_changes_only_for_index_inputs PASSED [ 79%]
tests/test_retrieval_upgrade.py::test_embedding_cache_makes_zero_calls_for_unchanged_chunks PASSED [ 81%]
tests/test_retrieval_upgrade.py::test_tokenizer_keeps_cve_and_cwe_ids_whole PASSED [ 82%]
tests/test_retrieval_upgrade.py::test_rrf_matches_hand_computed_k60 PASSED [ 84%]
tests/test_retrieval_upgrade.py::test_metadata_filter_is_applied_before_every_stage PASSED [ 85%]
tests/test_retrieval_upgrade.py::test_reranker_fallback_is_recorded PASSED [ 87%]
tests/test_retrieval_upgrade.py::test_reranker_fails_without_scores_when_primary_and_fallback_fail PASSED [ 89%]
tests/test_retrieval_upgrade.py::test_arm_2_path_never_calls_sparse_or_reranker PASSED [ 90%]
tests/test_retrieval_upgrade.py::test_eval_metrics_hand_computed_fixture PASSED [ 92%]
tests/test_retrieval_upgrade.py::test_bootstrap_ci_is_reproducible PASSED [ 93%]
tests/test_scanme.py::test_scanme_resolves_without_target_restriction PASSED [ 95%]
tests/test_scanme.py::test_scanme_nuclei_is_not_invoked PASSED           [ 96%]
tests/test_scanme.py::test_scanme_nmap_command_is_low_rate_and_not_aggressive PASSED [ 98%]
tests/test_wait.py::test_port_wait_timeout PASSED                        [100%]

============================= 64 passed in 5.14s ==============================
```
