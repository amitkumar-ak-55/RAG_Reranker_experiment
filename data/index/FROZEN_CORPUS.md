# Frozen corpus

- Frozen at: 2026-11-05T22:32:54.049023+00:00
- Source: `data/kb/documents.jsonl`
- `corpus_sha256`: `8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc`
- Target seed count: 1142
- Distractor seed count: 120

## Counts by document type

| doc_type | count |
|---|---:|
| attack | 12 |
| cve | 1142 |
| cwe | 171 |
| distractor | 120 |
| nuclei | 582 |
## Counts by group

| group | count |
|---|---:|
| distractor | 236 |
| kev | 947 |
| positive | 844 |
## Rebuild verification

- `python kb_build.py --refresh` completed successfully.
- NVD target summary: requested 1142, found 1142, skipped 0, written 1142.
- NVD distractor summary: requested 120, found 120, skipped 0, written 120.
- `skipped.jsonl` contains no `CVE_NOT_FOUND_IN_NVD` entry for any final target.
- `manifest.json` contains SHA-256 hashes for every final target and distractor cached NVD JSON under `nvd_file_hashes`.

## Pytest output

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

============================= 65 passed in 32.89s =============================
```
