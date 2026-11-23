# IEEE Research Paper Artifact Package
## "Evaluating Deductive Claim-Verification (TypeSafe JEV) vs. Neural Cross-Encoders for Post-Retrieval Reranking in Security Hybrid RAG"

This package contains all empirical data, statistical test outputs, LaTeX tables, publication figures, methodology scripts, and frozen benchmark evaluation files needed to write the complete research paper.

---

### Folder Structure

```text
research_paper_package_300q/
│
├── README_RESEARCH_PACKAGE.md         <-- This guide
│
├── 01_paper_tables_and_summary/       <-- READY-TO-USE PAPER CONTENT (Overleaf & LaTeX)
│   ├── latex_tables.tex               <-- 4 IEEEtran/booktabs LaTeX tables ready to paste
│   ├── paper_summary.md               <-- Full analytical report with math formulas & draft prose
│   ├── summary_metrics.json           <-- Machine-readable numbers, 95% CIs, and p-values
│   └── figures/                       <-- ALL 4 PUBLICATION FIGURES (BOTH PNG & SVG)
│       ├── fig1_system_architecture.png   <-- Fig 1: End-to-End Pipeline & System Architecture (PNG)
│       ├── fig1_system_architecture.svg   <-- Fig 1: Vector SVG source
│       ├── fig2_ranking_metrics.png       <-- Fig 2: Recall@1, Recall@5, MRR@10, nDCG@5 Bar Chart (PNG)
│       ├── fig2_ranking_metrics.svg       <-- Fig 2: Vector SVG source
│       ├── fig3_latency_vs_accuracy.png   <-- Fig 3: Pareto Frontier (Latency vs. MRR@10) (PNG)
│       ├── fig3_latency_vs_accuracy.svg   <-- Fig 3: Vector SVG source
│       ├── fig4_answer_correctness.png    <-- Fig 4: Downstream Answer Correctness Distribution (PNG)
│       └── fig4_answer_correctness.svg    <-- Fig 4: Vector SVG source
│
├── 02_full_experiment_telemetry/      <-- RAW EMPIRICAL DATA (300 Questions, 3 Arms)
│   ├── per_question_results.csv       <-- 900 rows: question_id, arm, answers, latencies, tokens
│   ├── per_candidate_results.csv      <-- 9,000 rows: candidate rankings, scores, doc_ids, ranks
│   ├── generated_answers.jsonl        <-- Full LLM generated answers & configurations
│   ├── experiment_metadata.json       <-- Provenance, environment, model versions, hashes
│   ├── checkpoint.json                <-- Checkpoint proof of 300 completed questions
│   └── structured_events.json         <-- Execution event audit trail
│
├── 03_evaluation_benchmark/           <-- FROZEN BENCHMARK DATASET
│   ├── eval_hard_300.jsonl            <-- 300 frozen hard security evaluation questions
│   ├── index_manifest.json            <-- Knowledge base manifest (17,871 chunks, BGE-base)
│   └── manifest.json                  <-- Corpus provenance manifest
│
└── 04_methodology_and_code/           <-- PIPELINE CODE FOR REPRODUCIBILITY
    ├── pipeline.py                    <-- Core A/B/C experiment runner
    ├── paper_report.py                <-- Paper artifact and metric synthesis script
    ├── evaluation.py                  <-- IR & downstream evaluation metrics (MRR, nDCG, accuracy)
    ├── statistics.py                  <-- Bootstrap CIs, Wilcoxon signed-rank, Holm-Bonferroni
    ├── jev_batch.py                   <-- TypeSafe JEV batch adapter & relevance prompt
    ├── client.py                      <-- Jina reranker client adapter
    └── generation.py                  <-- Production answer generation provider adapter
```

---

### Key Empirical Numbers to Highlight in the Paper

1. **Ranking Performance (Table 1)**:
   - **Recall@1**: TypeSafe JEV achieves **83.00%** vs. Jina's **74.00%** and Baseline Hybrid's **56.33%** (+26.67% over baseline, +9.00% over Jina).
   - **Recall@5**: JEV achieves **94.00%** vs. Jina's **93.67%** and Baseline's **89.00%**.
   - **MRR@10**: JEV achieves **0.8767** vs. Jina's **0.8201** and Baseline's **0.6920**.
   - **nDCG@5**: JEV achieves **0.8908** vs. Jina's **0.8470** and Baseline's **0.7341**.

2. **Statistical Significance (Table 4)**:
   - JEV vs. Baseline: Wilcoxon $W = 497.0$, $p < 0.0001$ (Holm-Bonferroni $p_{adj} < 0.001$).
   - JEV vs. Jina: Wilcoxon $W = 570.5$, $p = 0.0002$ (Holm-Bonferroni $p_{adj} = 0.0002$).
   - *Both ranking gains are statistically significant at $p < 0.001$.*

3. **Operational Latency & Efficiency (Table 3)**:
   - JEV Mean Rerank Latency: **1,003.3 ms** (Median: 801.8 ms).
   - Jina Mean Rerank Latency: **1,373.7 ms** (Median: 1,131.0 ms).
   - JEV is **27.0% faster on average and 29.1% faster on median** than the neural cross-encoder.

4. **Downstream Answer Correctness (Table 2)**:
   - Unambiguous Gold CVE Identification: JEV **77.33%** vs. Jina **76.67%** vs. Baseline **72.33%**.
   - Model Refusal / "Insufficient Evidence": JEV **3.33%** vs. Jina **4.67%** vs. Baseline **7.33%** (more than 50% drop in refusals).

---

### How to Insert Figures

All figures are provided as PNG and SVG in `01_paper_tables_and_summary/figures/`:
* In Microsoft Word / Docs: Insert the `.png` file directly.
* In LaTeX / Overleaf: Use `\includegraphics[width=\linewidth]{figures/figX_name.png}`.
