# Jina reranker experiment

This folder isolates a research-grade three-arm comparison from the production
RAG app: Hybrid RAG baseline, Hybrid RAG + hosted Jina, and Hybrid RAG + JEV.
It preserves the shared top-10 candidate set, evaluates top-5 evidence, maps
gold CVEs to all matching KB records, and stores auditable manifests and logs.

## Configuration

The existing root `.env` names are used:

```text
JINA_API_KEY_1=
JINA_API_KEY_2=
JINA_BASE_URL=
JINA_RERANKER_MODEL=
JINA_RERANK_TIMEOUT_SECONDS=30
JINA_RERANK_CANDIDATE_LIMIT=20
JINA_RERANK_RESULT_LIMIT=5
```

Keys are selected round-robin. If a request returns a rate-limit, auth, or
transient server response, the next configured key is tried once. Results
record only key-slot numbers, never key values.

## Validation and mock dry run

From the repository root:

```powershell
python -m reranker_experiment.cli validate-dataset
python -m reranker_experiment.cli mock-dry-run --provider mock --questions 3
```

The development run loads the frozen SQLite KB and embeddings, invokes the
existing dense + BM25 + RRF retrieval once per question, and shares its
top-10 candidates across all three arms. Jina and JEV are deterministic
content-only mock providers, and answer generation is selected explicitly with
`--provider mock`; no external API calls are made. `ProductionAnswerProvider` in `generation.py`
adapts the unchanged `rag_verify_lab.rag.answer.answer_question` function for
an explicitly injected production-compatible run. It passes each arm's own
selected top-five evidence while using one shared model, token limit, and
temperature setting; it does not change the production implementation.
It writes an artifact under
`data/experiments/mock_pipeline_*` and is not an empirical result.

Production execution requires `--provider production` and is available only
through the bounded `pilot` command, which accepts one to three questions:

```powershell
python -m reranker_experiment.cli pilot --provider production --questions 1
```

The explicitly authorized full run processes all 300 frozen questions:

```powershell
python -m reranker_experiment.cli full --provider production
python -m reranker_experiment.cli full --provider production --resume
python -m reranker_experiment.cli full --provider production --resume --output-dir data/experiments/production_full_<run_id>
```

The full command writes a per-question checkpoint and can resume from the next
incomplete question. Resume validates provider, dataset, KB, source, retrieval,
and answer-generation fingerprints before continuing. Pass `--output-dir` when
resuming an existing run.

Missing production configuration fails before index loading or retrieval.
There is no implicit fallback between providers. Before an authorized pilot,
validate the actual provider contracts and inspect the mock artifact. Use the existing TypeSafe System One contract
(`POST /v1/systemone`, `state`, keyed `questions`, `answers`) and the hosted
Jina rerank endpoint configured in `.env`; credentials are never logged.

## Output and analysis

Each run stores `experiment_metadata.json`, frozen-index metadata, shared
candidate snapshots, per-arm ranking/evidence/answer records, checkpoint
state, and structured events. Answer records include provider/model,
generation configuration, latency, optional token/cost telemetry, success or
failure status, and sanitized error fields. Unavailable token and cost values
remain null. The development command is capped at three questions; it does not
run the 300-question experiment.

## Live connectivity smoke test

The isolated smoke test uses one Jina query/two documents and one JEV query/two
named Noul candidate questions. It is disabled by default and requires
`--live-approved`; use `--provider jina`, `--provider jev`, or `--provider both`
to test providers independently.

```powershell
python -m reranker_experiment.live_connectivity_smoke
python -m reranker_experiment.live_connectivity_smoke --live-approved --provider jina
python -m reranker_experiment.live_connectivity_smoke --live-approved --provider jev
```

Only run the approved forms when intentionally consuming live API credits.
The smoke test has a 10-second timeout and makes no automatic retries. It does
not load the 300-question dataset or run retrieval, answer generation, or the
experiment runner.

## Tests

```powershell
pytest reranker_experiment/tests
```

