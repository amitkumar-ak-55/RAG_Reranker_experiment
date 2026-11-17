# Fixed Evaluation Question Set

Generated from the frozen `data/kb/documents.jsonl` corpus
(`8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc`).
No retrieval, arm, LLM, or JEV call is used.

## Counts

- Split seed: `42`
- `dev`: 1,317
- `test`: 3,335
- Total: 4,652
- `existence`: 1,131
- `distractor_existence`: 115
- `cwe`: 1,009
- `cvss`: 1,128
- `kev`: 1,253
- `unanswerable`: 16

Existence questions are emitted only where the source record has a CPE
vendor/product, as required by the question wording. CWE questions are emitted
only when at least one catalog CWE has a corresponding frozen CWE evidence
record.

## Question types

- `existence`: target CVE and CPE vendor/product; gold `yes`.
- `distractor_existence`: distractor CVE and its own CPE vendor/product; gold `yes`.
- `cwe`: target's sorted catalog CWE IDs; CWE records are additional evidence.
- `cvss`: target's recorded score and version.
- `kev`: target or distractor's recorded CISA KEV boolean.
- `unanswerable`: live-NVD-confirmed CVE absent from the frozen corpus; gold
  `insufficient evidence` and no evidence IDs.

## Leakage checks

- Corpus hash verified: pass.
- Gold-answer text leakage: pass.
- CWE ID leakage in CWE questions: pass.
- Target/distractor evidence separation: pass.
- Evidence IDs exist: pass.
- Unanswerable IDs absent: pass.
- Source hashes recompute: pass.
- Target split consistency: pass.
- Leakage failures: **0**.

## Regeneration

```powershell
python -m rag_verify_lab.eval_questions
```

The generator checks the corpus SHA-256 before producing output. The 16
unanswerable IDs were each confirmed as present by NVD and absent from the
frozen corpus on 2026-11-06; no NVD response is used as gold evidence.

## Pytest output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\bhagy\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\bhagy\Desktop\CysekRAG
configfile: pytest.ini
plugins: anyio-4.13.0
collecting ... collected 70 items

tests/test_arm_e.py::test_arm_e_ranks_scores_and_breaks_ties_by_bm25_rank PASSED
tests/test_arm_e.py::test_candidate_cap_sets_flag PASSED
tests/test_arm_e.py::test_precision_at_k_handles_fewer_gold_items PASSED
tests/test_arm_e.py::test_arm_e_is_not_configured_without_jev PASSED
tests/test_arm_e.py::test_jev_scoring_uses_choice_and_noul_schema PASSED
tests/test_authorization.py::test_scan_requires_authorization PASSED
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.1] PASSED
tests/test_authorization.py::test_scan_target_formats_are_accepted[example.test] PASSED
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/24] PASSED
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/32] PASSED
tests/test_authorization.py::test_scan_target_formats_are_rejected[10.0.0.0/8] PASSED
tests/test_authorization.py::test_scan_target_formats_are_rejected[not a host!] PASSED
tests/test_authorization.py::test_scan_job_stores_authorization_and_metadata PASSED
tests/test_cli.py::test_scan_requires_authorized PASSED
tests/test_cli.py::test_scan_rejects_invalid_target PASSED
tests/test_cli.py::test_scanme_rejects_nuclei PASSED
tests/test_cli.py::test_check_jev_exit_codes PASSED
tests/test_eval_questions.py::test_each_question_type_fixture_answers PASSED
tests/test_eval_questions.py::test_target_never_in_both_splits PASSED
tests/test_eval_questions.py::test_leakage_check_catches_gold_answer PASSED
tests/test_eval_questions.py::test_unanswerable_id_present_is_rejected PASSED
tests/test_eval_questions.py::test_regeneration_is_identical PASSED
tests/test_kb_build.py::test_every_record_has_exactly_the_19_keys PASSED
tests/test_kb_build.py::test_text_is_byte_identical_to_fixture_input PASSED
tests/test_kb_build.py::test_distractor_sharing_cwe_is_admitted_with_rule_cwe PASSED
tests/test_kb_build.py::test_distractor_sharing_only_vendor_is_rejected PASSED
tests/test_kb_build.py::test_distractor_sharing_vendor_product_is_admitted_with_rule_vendor_product PASSED
tests/test_kb_build.py::test_distractor_sharing_both_records_cwe_first_and_also PASSED
tests/test_kb_build.py::test_kev_distractor_is_rejected PASSED
tests/test_kb_build.py::test_attack_id_missing_from_bundle_is_skipped PASSED
tests/test_kb_build.py::test_revoked_attack_technique_is_skipped PASSED
tests/test_kb_build.py::test_valid_attack_technique_builds_correct_record PASSED
tests/test_kb_build.py::test_cwe_referenced_by_target_and_distractor_appears_once_with_group_positive PASSED
tests/test_kb_build.py::test_targets_total_equals_positive_cves_plus_kev_cves PASSED
tests/test_kb_build.py::test_nuclei_published_and_last_modified_are_null PASSED
tests/test_kb_build.py::test_every_skipped_reason_is_in_the_allowed_list PASSED
tests/test_metrics.py::test_claim_metrics PASSED
tests/test_parsers.py::test_nmap_parser PASSED
tests/test_parsers.py::test_nuclei_parser PASSED
tests/test_queue.py::test_queue_runs_one_at_a_time_and_cancel PASSED
tests/test_regressions.py::test_local_models_produce_embeddings_without_openrouter PASSED
tests/test_regressions.py::test_semantic_embedding_retrieves_paraphrase PASSED
tests/test_regressions.py::test_jev_clean_skip PASSED
tests/test_regressions.py::test_jev_uses_system_one_api PASSED
tests/test_regressions.py::test_jev_health_success PASSED
tests/test_regressions.py::test_jev_health_auth_failure PASSED
tests/test_regressions.py::test_jev_health_model_or_endpoint_failure PASSED
tests/test_regressions.py::test_jev_health_timeout_and_connection_refused PASSED
tests/test_regressions.py::test_jev_health_blank_config PASSED
tests/test_regressions.py::test_jev_url_checker_reports_endpoint_path PASSED
tests/test_regressions.py::test_cache_changes_with_model PASSED
tests/test_regressions.py::test_cost_unknown_when_prices_blank PASSED
tests/test_retrieval.py::test_retrieval_arms PASSED
tests/test_retrieval_upgrade.py::test_chunker_keeps_short_documents_whole_and_metadata PASSED
tests/test_retrieval_upgrade.py::test_chunker_splits_on_sentences_with_fifty_token_overlap PASSED
tests/test_retrieval_upgrade.py::test_index_version_changes_only_for_index_inputs PASSED
tests/test_retrieval_upgrade.py::test_embedding_cache_makes_zero_calls_for_unchanged_chunks PASSED
tests/test_retrieval_upgrade.py::test_tokenizer_keeps_cve_and_cwe_ids_whole PASSED
tests/test_retrieval_upgrade.py::test_rrf_matches_hand_computed_k60 PASSED
tests/test_retrieval_upgrade.py::test_metadata_filter_is_applied_before_every_stage PASSED
tests/test_retrieval_upgrade.py::test_reranker_fallback_is_recorded PASSED
tests/test_retrieval_upgrade.py::test_reranker_fails_without_scores_when_primary_and_fallback_fail PASSED
tests/test_retrieval_upgrade.py::test_real_configured_primary_reranker PASSED
tests/test_retrieval_upgrade.py::test_arm_2_path_never_calls_sparse_or_reranker PASSED
tests/test_retrieval_upgrade.py::test_eval_metrics_hand_computed_fixture PASSED
tests/test_retrieval_upgrade.py::test_bootstrap_ci_is_reproducible PASSED
tests/test_scanme.py::test_scanme_resolves_without_target_restriction PASSED
tests/test_scanme.py::test_scanme_nuclei_is_not_invoked PASSED
tests/test_scanme.py::test_scanme_nmap_command_is_low-rate-and-not-aggressive PASSED
tests/test_wait.py::test_port_wait_timeout PASSED

============================= 70 passed in 59.43s =============================
```
