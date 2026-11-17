# Author handoff: start here

This package contains the current paper draft, audited results, selected source artifacts, and paper figures. The Word document `Evidence-Grounded Hybrid Retrieval...docx` was not included because it is an earlier proposal with planned evaluations that are not supported by the completed 300-question run.

## Suggested workflow

1. Read `paper_draft.md`, `audit_for_paper.md`, and `FINAL_EXPERIMENT_REPORT.md` first.
2. Treat `final_eval_20261112T125646Z/tables/question_level_results.csv` as the primary row-level outcome source. Use `audit_for_paper.md` to resolve count definitions and the known stale configuration field.
3. Use `run_config.json`, `methods.md`, and the included `final_runner.py` / `jev.py` for the actual experiment setup and Arm D/E behavior.
4. Preserve uncertainty and limitations. Do not invent measurements, references, annotations, citations, or model behavior. Verify bibliographic references and the target IEEE venue's current template before submission.

## Verified headline findings

- 300 questions; five arms; exact parsed-CVE match scored as correct.
- LLM-only: 26/300 (8.7%); Vector RAG: 247/300 (82.3%); Hybrid RAG: 249/300 (83.0%); Hybrid + JEV gate: 244/300 (81.3%); direct JEV candidate selection: 262/300 (87.3%).
- Hybrid retrieval placed the gold CVE in its top five for 285/300 questions (95.0%). This measures candidate coverage, not answer correctness or causal attribution.
- Hybrid RAG vs. Hybrid + JEV: five C-only correct outcomes, zero D-only; exact two-sided McNemar p=0.0625. The run provides no evidence that this JEV verification gate improved Hybrid RAG.
- Arm E selected a CVE directly from BM25-derived candidates. It did not produce a confidence-ranked list for an LLM and did not test JEV-selected context followed by LLM generation.
- Reported JEV spend: $0.09 combined for 599 calls, with no per-arm split. GPT-6 Luna was not used; any Luna amount is only a hypothetical rate calculation.

## Important data cautions

- The Vector RAG breakdown is 247 correct, 51 wrong CVEs, 1 blank/invalid answer (Q-0594), and 1 provider error.
- `run_config.json` contains an inherited Arm E `answer_calls` value that conflicts with the final implementation path and row-level usage artifacts. The audit explains this discrepancy; report zero answer-model calls for E in the final path.
- The blind audit was not run. Raw JEV decision traces were not retained, so do not attribute each withheld Arm D answer to a specific internal JEV rationale.
- Do not use a cost-versus-accuracy plot as a monetary comparison; per-arm observed answer-provider costs are unavailable.

## Figure files

- `fig2_accuracy_bar.png`: main exact-match accuracy chart.
- `fig5_retrieval_coverage_vs_answer_accuracy.svg`: retrieval coverage compared with answer accuracy.
- `fig3_accuracy_by_difficulty.png`: optional supplementary chart.

No `.env`, API keys, or credentials are included.
