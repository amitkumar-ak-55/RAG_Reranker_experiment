# Graph Report - CysekRAG  (2026-11-06)

## Corpus Check
- Corpus is ~20,029 words - fits in a single context window. You may not need a graph.

## Summary
- 456 nodes · 1430 edges · 15 communities (12 shown, 3 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 71 edges (avg confidence: 0.91)
- Token cost: 1,200 input · 850 output

## Community Hubs (Navigation)
- Web API & Routes
- JEV & LLM Verification
- Dense Embeddings & Models
- Knowledge Base Ingestion
- CLI & Database Core
- Retrieval Evaluation Metrics
- Scanner Engine & Targets
- Adversarial Question Benchmark
- Test Suite & Fixtures
- Question Generation Tooling
- Project Specs & Overview
- Setup & Environment Config
- JEV Protocol & Governance

## God Nodes (most connected - your core abstractions)
1. `db_session()` - 49 edges
2. `run_experiment()` - 32 edges
3. `build_index_report()` - 26 edges
4. `FindingIndex` - 23 edges
5. `main()` - 22 edges
6. `Question` - 20 edges
7. `jev_health()` - 19 edges
8. `VM` - 18 edges
9. `retrieve()` - 18 edges
10. `run_retrieval()` - 16 edges

## Surprising Connections (you probably didn't know these)
- `test_jev_health_auth_failure()` --indirect_call--> `jev_health()`  [INFERRED]
  tests/test_regressions.py → rag_verify_lab/verify/jev_health.py
- `test_jev_health_blank_config()` --indirect_call--> `jev_health()`  [INFERRED]
  tests/test_regressions.py → rag_verify_lab/verify/jev_health.py
- `test_jev_health_model_or_endpoint_failure()` --indirect_call--> `jev_health()`  [INFERRED]
  tests/test_regressions.py → rag_verify_lab/verify/jev_health.py
- `test_jev_health_timeout_and_connection_refused()` --indirect_call--> `jev_health()`  [INFERRED]
  tests/test_regressions.py → rag_verify_lab/verify/jev_health.py
- `test_distractor_sharing_both_records_cwe_first_and_also()` --calls--> `qualify_distractor()`  [EXTRACTED]
  tests/test_kb_build.py → kb_build.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Project Governance & JEV Verification Requirements** — agents_project_spec, agents_rules, readme_jev_contract [INFERRED 0.85]

## Communities (15 total, 3 thin omitted)

### Community 0 - "Web API & Routes"
Cohesion: 0.08
Nodes (52): AuthorizationInput, cancel_job(), config(), create_image(), create_question(), create_vm(), delete_question(), delete_vm() (+44 more)

### Community 1 - "JEV & LLM Verification"
Cohesion: 0.05
Nodes (33): jev_health_route(), Settings, percentile(), summarize(), Answer, answer_question(), _price(), citation_correctness() (+25 more)

### Community 2 - "Dense Embeddings & Models"
Cohesion: 0.10
Nodes (32): _device(), download_models(), embedding_model(), embedding_tokenizer(), encode(), ModelLoadError, rerank(), reranker_manifest() (+24 more)

### Community 3 - "Knowledge Base Ingestion"
Cohesion: 0.09
Nodes (23): compute_sha256(), extract_cpe_vendor_product(), fetch_nvd_cve(), load_env_file(), main(), make_record(), make_title(), parse_attack_bundle() (+15 more)

### Community 4 - "CLI & Database Core"
Cohesion: 0.11
Nodes (33): _arms(), _check_jev(), main(), _parser(), _valid_ports(), _wait_for_job(), ArmResult, Base (+25 more)

### Community 5 - "Retrieval Evaluation Metrics"
Cohesion: 0.14
Nodes (26): bootstrap(), mrr(), ndcg10(), precision_at_k(), recall_at_k(), run_retrieval(), FindingIndex, index_version() (+18 more)

### Community 6 - "Scanner Engine & Targets"
Cohesion: 0.12
Nodes (19): _enqueue_scan(), scan(), _scan(), _is_ip(), NmapResult, parse_nmap_xml(), resolve_target(), run_nmap() (+11 more)

### Community 7 - "Adversarial Question Benchmark"
Cohesion: 0.21
Nodes (22): build_questions(), _confuser_attributes(), _confuser_is_weak(), _confusers(), _has_six_word_run(), main(), _normal_words(), _product() (+14 more)

### Community 8 - "Test Suite & Fixtures"
Cohesion: 0.14
Nodes (8): Job, now(), JobQueue, Work, test_scan_job_stores_authorization_and_metadata(), test_scan_target_formats_are_accepted(), test_scan_target_formats_are_rejected(), test_queue_runs_one_at_a_time_and_cancel()

### Community 9 - "Question Generation Tooling"
Cohesion: 0.25
Nodes (13): generate_questions(), main(), _product_name(), _question(), _read_jsonl(), _source_hash(), validate_questions(), fixture_corpus() (+5 more)

### Community 10 - "Project Specs & Overview"
Cohesion: 0.67
Nodes (3): rag-verify-lab Project Specification, rag-verify-lab System Overview, Evaluation & Testing Pipeline

### Community 11 - "Setup & Environment Config"
Cohesion: 0.67
Nodes (3): Application Setup & Deployment, Core Python Dependencies, Knowledge Base Tooling Dependencies

## Knowledge Gaps
- **5 isolated node(s):** `rag-verify-lab Project Specification`, `Application Setup & Deployment`, `Evaluation & Testing Pipeline`, `JEV API Contract & Verification Protocol`, `Knowledge Base Tooling Dependencies`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 73 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `db_session()` connect `Web API & Routes` to `Dense Embeddings & Models`, `CLI & Database Core`, `Retrieval Evaluation Metrics`, `Scanner Engine & Targets`, `Test Suite & Fixtures`?**
  _High betweenness centrality (0.068) - this node is a cross-community bridge._
- **Are the 5 inferred relationships involving `run_experiment()` (e.g. with `Finding` and `Question`) actually correct?**
  _`run_experiment()` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `rag-verify-lab Project Specification`, `Application Setup & Deployment`, `Evaluation & Testing Pipeline` to the rest of the system?**
  _5 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Web API & Routes` be split into smaller, more focused modules?**
  _Cohesion score 0.07552973342447027 - nodes in this community are weakly interconnected._
- **Why does `run_experiment()` connect `CLI & Database Core` to `Web API & Routes`, `JEV & LLM Verification`, `Dense Embeddings & Models`, `Retrieval Evaluation Metrics`, `Test Suite & Fixtures`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `FindingIndex` (e.g. with `hybrid_search()` and `retrieve()`) actually correct?**
  _`FindingIndex` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `JEV & LLM Verification` be split into smaller, more focused modules?**
  _Cohesion score 0.05454545454545454 - nodes in this community are weakly interconnected._