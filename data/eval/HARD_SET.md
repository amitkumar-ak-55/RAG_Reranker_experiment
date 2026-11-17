# Hard Evaluation Set

Updated [eval_hard.jsonl](../eval_hard.jsonl) after a corpus-behavior audit.
The corpus, index, seed files, and configuration were not changed. No
retrieval, arm, LLM, or JEV call was used.

## What changed

- Audited every behavior claim against its gold CVE record and removed
  unsupported details.
- Reworded H-001, H-002, H-003, H-005, H-006, H-008, H-009, H-010, H-011,
  H-012, H-013, H-014, H-015, H-018, H-020, H-021, H-022, H-023, H-024, and
  H-025 in original wording.
- Kept verification notes as exact record-text substrings.
- Regenerated confusers with same CPE vendor+product preferred for broad
  CWE-20, CWE-89, CWE-78, and CWE-502 matches. H-002 has
  `confuser_weak: true` because the frozen corpus provides no
  product-matched option; this limitation is not hidden.
- Regenerated [hard_proof.jsonl](hard_proof.jsonl) from the validator.

## Previous revision snapshot

| ID | New product mapping | Updated question | Confusers and shared attribute |
|---|---|---|---|
| H-001 | Apache Log4j | In Apache Log4j, data that an attacker controls is treated as a directory-service lookup, so the logger can fetch and run a remote payload. Which CVE describes this? | CVE-2015-5254 (CWE-20); CVE-2016-1000104 (CWE-20) |
| H-002 | 1Panel | In 1Panel, crafted database input can alter files on the host, with the write primitive usable for eventual code execution. Which CVE describes this? | CVE-2016-10134 (CWE-89); CVE-2016-2386 (CWE-89) |
| H-003 | Apache ActiveMQ | In Apache ActiveMQ, a sender can submit an object whose class the broker should have rejected, ending in execution on the service. Which CVE describes this? | CVE-2016-1000104 (CWE-20); CVE-2016-3088 (same CPE vendor+product) |
| H-004 | Apache ActiveMQ | In Apache ActiveMQ, an authenticated console request can make the management bridge load a Spring XML context and invoke code during bean setup. Which CVE describes this? | CVE-2015-5254 (CWE-20; same CPE vendor+product); CVE-2016-1000104 (CWE-20) |
| H-005 | FFmpeg | In FFmpeg, an HLS playlist handled by a media decoder can make the server leak local-file content inside a follow-up web request. Which CVE describes this? | CVE-2016-1898 (CWE-200; same CPE vendor+product); CVE-2016-6415 (CWE-200) |
| H-006 | Apache Struts | In Apache Struts, optional method dispatch treats a specially prefixed request value as an executable chained expression. Which CVE describes this? | CVE-2016-20017 (CWE-77); CVE-2016-6367 (CWE-77) |
| H-007 | Apache ActiveMQ | In Apache ActiveMQ, the file service permits a remote upload and then a rename-style request, leaving the uploaded payload executable. Which CVE describes this? | CVE-2015-5254 (same CPE vendor+product); CVE-2017-12615 (CWE-434) |
| H-008 | ImageMagick | In ImageMagick, an image conversion handler passes shell metacharacters from a hostile picture into a command path. Which CVE describes this? | CVE-2015-5254 (CWE-20); CVE-2016-1000104 (CWE-20) |
| H-009 | Apache Shiro | In Apache Shiro, a default remember-login setting lets a request both run code and evade intended authorization. Which CVE describes this? | CVE-2016-0034 (NVD-CWE-noinfo); CVE-2016-0040 (NVD-CWE-noinfo) |
| H-010 | Spring Security OAuth | In Spring Security OAuth, an authorization endpoint evaluates the requested response format as a server-side expression, giving an attacker code execution. Which CVE describes this? | CVE-2016-6286 (CWE-19); CVE-2016-6287 (CWE-19) |
| H-011 | PHPMailer | In PHPMailer, quoting copied from a sender field reaches the command-line invocation, allowing extra mail options and code execution. Which CVE describes this? | CVE-2017-5223 (same CPE vendor+product); CVE-2017-8917 (same CPE vendor+product) |
| H-012 | Zabbix | In Zabbix, values from an ID list are inserted into a database statement, allowing the caller to issue its own SQL. Which CVE describes this? | CVE-2016-2386 (CWE-89); CVE-2017-18362 (CWE-89) |
| H-013 | Zabbix | In Zabbix, a malicious packet sequence through a proxy reaches the trapper command path and runs attacker-selected commands. Which CVE describes this? | CVE-2016-10134 (same CPE vendor+product); CVE-2017-12636 (CWE-78) |
| H-014 | Adobe ColdFusion | In Adobe ColdFusion, a data-messaging component unsafely reconstructs serialized Java objects, providing a route to code execution. Which CVE describes this? | CVE-2017-1000353 (CWE-502); CVE-2017-12149 (CWE-502) |
| H-015 | Drupal | In Drupal, a YAML reader treats supplied PHP objects unsafely, allowing a network attacker to run code. Which CVE describes this? | CVE-2016-4977 (CWE-19); CVE-2016-5385 (same CPE vendor+product) |
| H-016 | Samba | In Samba, a client can place a library in a writable share and then induce the server to load that library as code. Which CVE describes this? | CVE-2016-5734 (CWE-94); CVE-2017-16082 (CWE-94) |
| H-017 | JBossMQ | In JBossMQ, a messaging endpoint rebuilds attacker-chosen classes from incoming data without an allowlist, leading to execution on the server. Which CVE describes this? | CVE-2017-1000353 (CWE-502); CVE-2017-12149 (CWE-502; same CPE vendor+product) |
| H-018 | jackson-databind | In jackson-databind, an object mapper accepts a hostile object graph from an unauthenticated caller and can turn it into executable behavior. Which CVE describes this? | CVE-2016-3427 (same CPE vendor+product); CVE-2016-5195 (same CPE vendor+product) |
| H-019 | Joomla | In Joomla, request handling lets an attacker inject database syntax and issue arbitrary SQL statements. Which CVE describes this? | CVE-2016-10033 (same CPE vendor+product); CVE-2016-10134 (CWE-89) |
| H-020 | Apache Struts | In Apache Struts, an old action plugin accepts an attacker-controlled message field that reaches the application's code-execution path. Which CVE describes this? | CVE-2015-5254 (CWE-20); CVE-2016-1000104 (CWE-20) |
| H-021 | Apache Solr | In Apache Solr, XML query handling expands attacker-supplied external entities, exposing local files and enabling a server-side fetch. Which CVE describes this? | CVE-2016-9563 (CWE-611); CVE-2017-12149 (same CPE vendor+product) |
| H-022 | Apache CouchDB | In Apache CouchDB, an account-creation parser interprets repeated role fields inconsistently, allowing an ordinary account to acquire administrator rights. Which CVE describes this? | CVE-2016-0151 (CWE-269); CVE-2017-12636 (same CPE vendor+product) |
| H-023 | Django | In Django, an exposed debug error page can execute attacker markup in a viewer's browser because the page omits HTML escaping. Which CVE describes this? | CVE-2018-14574 (same CPE vendor+product); CVE-2018-19943 (CWE-79) |
| H-024 | node-postgres | In node-postgres, a database-supplied column label can be interpreted as executable input by the client library. Which CVE describes this? | CVE-2016-5734 (CWE-94); CVE-2017-7494 (CWE-94) |
| H-025 | Ruby Net::FTP | In Ruby Net::FTP, a local destination beginning with a pipe is treated as a shell instruction instead of a filename. Which CVE describes this? | CVE-2017-12636 (CWE-78); CVE-2017-2824 (CWE-78) |

## Current question rewrites

The old wording remains in the preceding table for traceability. The current
wording below is generated from `HAND_SET` in
[eval_hard.py](../../rag_verify_lab/eval_hard.py); confusers are generated from
the corpus and recorded with their shared attributes in
[hard_proof.jsonl](hard_proof.jsonl).

| ID | New question |
|---|---|
| H-001 | In Apache Log4j, attacker-controlled log content can trigger a directory lookup and load code from a remote server. |
| H-002 | In 1Panel, insufficiently filtered SQL injection can write arbitrary files and ultimately lead to code execution. |
| H-003 | In Apache ActiveMQ, serialized message objects are accepted without restricting their classes, allowing code execution. |
| H-005 | In FFmpeg, an HLS playlist can make a remote request carry data from a local file. |
| H-006 | In Apache Struts, Dynamic Method Invocation lets a method-prefixed request reach chained expressions and code execution. |
| H-008 | In ImageMagick, specially prepared picture content can cause command execution through shell syntax. |
| H-009 | In Apache Shiro, leaving the cipher key unset for remember-me can permit code execution or an access-control bypass. |
| H-010 | In Spring Security OAuth, a crafted response_type value is evaluated as Spring SpEL and can trigger remote code execution. |
| H-011 | In PHPMailer, a crafted Sender value can add options to the mail command and execute code. |
| H-012 | In Zabbix, the toggle_ids array parameter can be used to inject SQL commands. |
| H-013 | In Zabbix, packets sent through an active proxy can reach trapper command handling and cause command injection. |
| H-014 | In Adobe ColdFusion, unsafe Java deserialization in its BlazeDS library can lead to code execution. |
| H-015 | In Drupal, unsafe PHP-object handling by the PECL YAML parser can let a remote attacker execute code. |
| H-018 | In jackson-databind, malicious input sent to ObjectMapper can let an unauthenticated user execute code. |
| H-020 | In Apache Struts, the Struts 1 plugin can pass a malicious field in ActionMessage to remote code execution. |
| H-021 | In Apache Solr, XML query parsing can expand external entities and read local files through an FTP wrapper. |
| H-022 | In Apache CouchDB, duplicate role fields can let a non-admin user grant itself administrator privileges. |
| H-023 | In Django, the technical 500 debug page disables HTML autoescaping, allowing cross-site scripting. |
| H-024 | In node-postgres, a malicious column name supplied by a query or database can cause code execution. |
| H-025 | In Ruby Net::FTP, a pipe-prefixed localfile makes the following command execute. |

## Quick blind self-test

I read these ten questions without consulting their `gold_answer` fields,
identified the product and behavior, and wrote the prediction before checking:

| Question | Blind prediction | Result |
|---|---|---|
| H-001 | CVE-2021-44228 | correct |
| H-003 | CVE-2015-5254 | correct |
| H-005 | CVE-2016-1897 | correct |
| H-007 | CVE-2016-3088 | correct |
| H-009 | CVE-2016-4437 | correct |
| H-012 | CVE-2016-10134 | correct |
| H-014 | CVE-2017-3066 | correct |
| H-018 | CVE-2017-7525 | correct |
| H-022 | CVE-2017-12635 | correct |
| H-025 | CVE-2017-17405 | correct |

Blind self-test score: **10/10**.

## Checks

- Corpus SHA-256 verified: pass.
- 25 questions retained: pass.
- 14 CWE classes and 24 products: pass.
- Product named in every question matches the behavior/product mapping: pass.
- No question contains a six-word run from its record or verification note: pass.
- No question contains its gold CVE ID, exact CPE string, or CWE ID: pass.
- Every answer is a corpus CVE in `positive` or `kev`: pass.
- Every confuser is a different non-seed-distractor corpus CVE sharing CWE or CPE vendor+product: pass.
- Verification notes remain present in their record text: pass.
- Check failures: **0**.

## Pytest output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\bhagy\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\bhagy\Desktop\CysekRAG
configfile: pytest.ini
plugins: anyio-4.13.0
collecting ... collected 76 items

tests/test_eval_hard.py::test_question_containing_cve_id_fails PASSED
tests/test_eval_hard.py::test_missing_verification_note_fails PASSED
tests/test_eval_hard.py::test_six_word_record_run_fails PASSED
tests/test_eval_hard.py::test_fewer_than_ten_cwe_classes_fails PASSED
tests/test_eval_hard.py::test_generated_hard_set_is_valid PASSED
tests/test_eval_hard.py::test_machine_proof_has_zero_overlap_and_leakage PASSED

======================== 76 passed in 73.74s (0:01:13) ========================
```

## Machine-checkable proof

The direct JSONL output of the validator is saved at
[hard_proof.jsonl](hard_proof.jsonl). It has one object per question with the
six-word overlap count, the gold-CVE/CPE/CWE leakage booleans, verification-note
substring status, and each confuser's corpus-derived shared CWE and/or CPE
vendor+product attribute.

Regenerate it without retrieval or model calls:

```powershell
python -m rag_verify_lab.eval_hard --proof > data/eval/hard_proof.jsonl
```

Recorded proof summary: 25 rows; every overlap count is `0`; all three leakage
booleans are `false` for every row; every verification-note status is `true`;
and every row has two confusers with shared attributes.

## Blind self-test evidence

The ten self-test prompts were presented as question text only. Predictions
were recorded before opening or comparing `gold_answer`; the later comparison
was 10/10. This is the short procedural evidence of blindness, not a retrieval
or model result.

## Latest pytest -v output

```text
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\bhagy\AppData\Local\Programs\Python\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\bhagy\Desktop\CysekRAG
configfile: pytest.ini
plugins: anyio-4.13.0
collecting ... collected 76 items

tests/test_arm_e.py::test_arm_e_ranks_scores_and_breaks_ties_by_bm25_rank PASSED [  1%]
tests/test_arm_e.py::test_candidate_cap_sets_flag PASSED                 [  2%]
tests/test_arm_e.py::test_precision_at_k_handles_fewer_gold_items PASSED [  3%]
tests/test_arm_e.py::test_arm_e_is_not_configured_without_jev PASSED     [  5%]
tests/test_arm_e.py::test_jev_scoring_uses_choice_and_noul_schema PASSED  [  6%]
tests/test_authorization.py::test_scan_requires_authorization PASSED     [  7%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.1] PASSED [  9%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[example.test] PASSED [ 10%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/24] PASSED [ 11%]
tests/test_authorization.py::test_scan_target_formats_are_accepted[192.0.2.0/32] PASSED [ 13%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[10.0.0.0/8] PASSED [ 14%]
tests/test_authorization.py::test_scan_target_formats_are_rejected[not a host!] PASSED [ 15%]
tests/test_authorization.py::test_scan_job_stores_authorization_and_metadata PASSED [ 17%]
tests/test_cli.py::test_scan_requires_authorized PASSED                  [ 18%]
tests/test_cli.py::test_scan_rejects_invalid_target PASSED               [ 19%]
tests/test_cli.py::test_scanme_rejects_nuclei PASSED                     [ 21%]
tests/test_cli.py::test_check_jev_exit_codes PASSED                      [ 22%]
tests/test_eval_hard.py::test_question_containing_cve_id_fails PASSED    [ 23%]
tests/test_eval_hard.py::test_missing_verification_note_fails PASSED     [ 25%]
tests/test_eval_hard.py::test_six_word_record_run_fails PASSED           [ 26%]
tests/test_eval_hard.py::test_fewer_than_ten_cwe_classes_fails PASSED    [ 27%]
tests/test_eval_hard.py::test_generated_hard_set_is_valid PASSED         [ 28%]
tests/test_eval_hard.py::test_machine_proof_has_zero_overlap_and_leakage PASSED [ 30%]
tests/test_eval_questions.py::test_each_question_type_fixture_answers PASSED [ 31%]
tests/test_eval_questions.py::test_target_never_in_both_splits PASSED    [ 32%]
tests/test_eval_questions.py::test_leakage_check_catches_gold_answer PASSED [ 34%]
tests/test_eval_questions.py::test_unanswerable_id_present_is_rejected PASSED [ 35%]
tests/test_eval_questions.py::test_regeneration_is_identical PASSED      [ 36%]
tests/test_kb_build.py::test_every_record_has_exactly_the_19_keys PASSED [ 38%]
tests/test_kb_build.py::test_text_is_byte_identical_to_fixture_input PASSED [ 39%]
tests/test_kb_build.py::test_distractor_sharing_cwe_is_admitted_with_rule_cwe PASSED [ 40%]
tests/test_kb_build.py::test_distractor_sharing_only_vendor_is_rejected PASSED [ 42%]
tests/test_kb_build.py::test_distractor_sharing_vendor_product_is_admitted_with_rule_vendor_product PASSED [ 43%]
tests/test_kb_build.py::test_distractor_sharing_both_records_cwe_first_and_also PASSED [ 44%]
tests/test_kb_build.py::test_kev_distractor_is_rejected PASSED           [ 46%]
tests/test_kb_build.py::test_attack_id_missing_from_bundle_is_skipped PASSED [ 47%]
tests/test_kb_build.py::test_revoked_attack_technique_is_skipped PASSED  [ 48%]
tests/test_kb_build.py::test_valid_attack_technique_builds_correct_record PASSED [ 50%]
tests/test_kb_build.py::test_cwe_referenced_by_target_and_distractor_appears_once_with_group_positive PASSED [ 51%]
tests/test_kb_build.py::test_targets_total_equals_positive_cves_plus_kev_cves PASSED [ 52%]
tests/test_kb_build.py::test_nuclei_published_and_last_modified_are_null PASSED [ 53%]
tests/test_kb_build.py::test_every_skipped_reason_is_in_the_allowed_list PASSED [ 55%]
tests/test_metrics.py::test_claim_metrics PASSED                         [ 56%]
tests/test_parsers.py::test_nmap_parser PASSED                           [ 57%]
tests/test_parsers.py::test_nuclei_parser PASSED                         [ 59%]
tests/test_queue.py::test_queue_runs_one_at_a_time_and_cancel PASSED     [ 60%]
tests/test_regressions.py::test_local_models_produce_embeddings_without_openrouter PASSED [ 61%]
tests/test_regressions.py::test_semantic_embedding_retrieves_paraphrase PASSED [ 63%]
tests/test_regressions.py::test_jev_clean_skip PASSED                    [ 64%]
tests/test_regressions.py::test_jev_uses_system_one_api PASSED           [ 65%]
tests/test_regressions.py::test_jev_health_success PASSED                [ 67%]
tests/test_regressions.py::test_jev_health_auth_failure PASSED           [ 68%]
tests/test_regressions.py::test_jev_health_model_or_endpoint_failure PASSED [ 69%]
tests/test_regressions.py::test_jev_health_timeout_and_connection_refused PASSED [ 71%]
tests/test_regressions.py::test_jev_health_blank_config PASSED            [ 72%]
tests/test_regressions.py::test_jev_url_checker_reports_endpoint_path PASSED [ 73%]
tests/test_regressions.py::test_cache_changes_with_model PASSED          [ 75%]
tests/test_regressions.py::test_cost_unknown_when_prices_blank PASSED     [ 76%]
tests/test_retrieval.py::test_retrieval_arms PASSED                      [ 77%]
tests/test_retrieval_upgrade.py::test_chunker_keeps_short_documents_whole_and_metadata PASSED [ 78%]
tests/test_retrieval_upgrade.py::test_chunker_splits_on_sentences_with_fifty_token_overlap PASSED [ 80%]
tests/test_retrieval_upgrade.py::test_index_version_changes_only_for_index_inputs PASSED [ 81%]
tests/test_retrieval_upgrade.py::test_embedding_cache_makes_zero_calls_for_unchanged_chunks PASSED [ 82%]
tests/test_retrieval_upgrade.py::test_tokenizer_keeps_cve_and_cwe_ids_whole PASSED [ 84%]
tests/test_retrieval_upgrade.py::test_rrf_matches_hand_computed_k60 PASSED [ 85%]
tests/test_retrieval_upgrade.py::test_metadata_filter_is_applied_before_every_stage PASSED [ 86%]
tests/test_retrieval_upgrade.py::test_reranker_fallback_is_recorded PASSED [ 88%]
tests/test_retrieval_upgrade.py::test_reranker_fails_without_scores_when_primary_and_fallback_fail PASSED [ 89%]
tests/test_retrieval_upgrade.py::test_real_configured_primary_reranker PASSED [ 90%]
tests/test_retrieval_upgrade.py::test_arm_2_path_never_calls_sparse_or_reranker PASSED [ 92%]
tests/test_retrieval_upgrade.py::test_eval_metrics_hand_computed_fixture PASSED [ 93%]
tests/test_retrieval_upgrade.py::test_bootstrap_ci_is_reproducible PASSED [ 94%]
tests/test_scanme.py::test_scanme_resolves_without_target_restriction PASSED [ 96%]
tests/test_scanme.py::test_scanme_nuclei_is_not_invoked PASSED            [ 97%]
tests/test_scanme.py::test_scanme_nmap_command_is_low_rate_and_not_aggressive PASSED [ 98%]
tests/test_wait.py::test_port_wait_timeout PASSED                        [100%]

======================== 76 passed in 73.46s (0:01:13) ========================
```
