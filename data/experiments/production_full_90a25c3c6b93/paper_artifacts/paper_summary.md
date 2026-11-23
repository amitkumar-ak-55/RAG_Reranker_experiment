# Empirical Evaluation Report: Post-Retrieval Reranker Study

This document aggregates the complete empirical evaluation for the research study:
**"Evaluating Deductive Claim-Verification (TypeSafe JEV) vs. Cross-Encoder Reranking in Security-Domain Hybrid RAG Systems."**

---

## 1. Experimental Metadata & Provenance

* **Evaluation Questions**: `300` frozen evaluation records ([eval_hard_300.jsonl](file:///C:/Users/bhagy/Desktop/CysekRAG/data/eval/final/eval_hard_300.jsonl))
* **Knowledge Base Scale**: 17,871 chunks / 17,863 documents ([data/app.db](file:///C:/Users/bhagy/Desktop/CysekRAG/data/app.db))
* **Embedding Model**: `BAAI/bge-base-en-v1.5` ($d=768$, unit $L_2$-normalized)
* **First-Stage Retrieval**: Dense Vector Search + BM25 Sparse Search + Reciprocal Rank Fusion (Candidate Budget $k=10$)
* **Evaluated Arms**:
  1. **Arm A (Baseline)**: Original hybrid retrieval order (negative rank score)
  2. **Arm B (Neural Cross-Encoder)**: Hosted Jina Reranker (`jina-reranker-v3.5`)
  3. **Arm C (Deductive Engine)**: TypeSafe JEV Batch Claim-Verification (`jev-latest`)
* **Answer Generation Provider**: `openai/gpt-oss-120b` ($T=\text{null}$, Max Tokens = 256, Top-5 Evidence)

---

## 2. Mathematical Metric Formulations

### Reciprocal Rank (RR) & Mean Reciprocal Rank (MRR@10)
$$\text{RR}(q) = \begin{cases} \frac{1}{\text{rank}_q}, & \text{if } 1 \le \text{rank}_q \le 10 \\ 0, & \text{if gold target not in top 10} \end{cases}$$
$$\text{MRR}@10 = \frac{1}{|Q|} \sum_{q=1}^{|Q|} \text{RR}(q)$$

### Normalized Discounted Cumulative Gain (nDCG@k)
$$\text{DCG}@k = \sum_{i=1}^k \frac{2^{\text{rel}_i} - 1}{\log_2(i + 1)}, \quad \text{nDCG}@k = \frac{\text{DCG}@k}{\text{IDCG}@k}$$
*(Binary relevance: $\text{rel}_i = 1$ if candidate $i$ contains the gold CVE, else $0$)*

### Exact Unambiguous Answer Accuracy
$$\text{Acc}_{\text{unambig}} = \frac{1}{|Q|} \sum_{q=1}^{|Q|} \mathbb{I}\Big(\mathcal{E}(\text{Answer}_q) = \{\text{GoldCVE}_q\}\Big)$$
*(Where $\mathcal{E}(\cdot)$ denotes normalized regex extraction matching standard and Unicode-hyphenated CVE identifiers)*

---

## 3. Core Evaluation Results

### Table 1: Retrieval & Reranking Performance Comparison

| Metric | Arm A: Baseline (Hybrid) | Arm B: Jina Reranker | Arm C: TypeSafe JEV | Best Performer |
| :--- | :---: | :---: | :---: | :---: |
| **Recall@1 (Hit@1)** | 56.33% | 74.00% | 83.00% | **Arm C (JEV)** |
| **Recall@5 (Hit@5)** | 89.00% | 93.67% | 94.00% | **Arm C (JEV)** |
| **Recall@10 (Pool Ceiling)** | 95.67% | 95.67% | 95.67% | Fixed ($k=10$) |
| **MRR@10** | **0.6920** (±0.367) | **0.8201** (±0.318) | **0.8767** (±0.285) | **Arm C (JEV)** |
| **nDCG@5** | **0.7341** (±0.342) | **0.8470** (±0.288) | **0.8908** (±0.267) | **Arm C (JEV)** |

---

### Table 2: Downstream Answer Quality & Verification

| Generation Outcome | Arm A: Baseline | Arm B: Jina Reranker | Arm C: TypeSafe JEV |
| :--- | :---: | :---: | :---: |
| **Unambiguous Gold Match (Accuracy)** | **72.33%** | **76.67%** | **77.33%** |
| **Gold Mention Rate (Total Hits)**   | 77.00% | 81.33% | 82.33% |
| **Refusal / "Insufficient Evidence"** | 7.33% | 4.67% | 3.33% |

---

### Table 3: Operational Latency & Efficiency Breakdown

| Latency Metric | Arm A: Baseline | Arm B: Jina Reranker | Arm C: TypeSafe JEV | JEV vs. Jina Advantage |
| :--- | :---: | :---: | :---: | :---: |
| **Reranking Latency (Mean)** | 0.0 ms | **1373.7 ms** | **1003.3 ms** | **+27.0% faster** |
| **Reranking Latency (Median)** | 0.0 ms | 1131.0 ms | 801.8 ms | - |
| **Reranking Latency (P95)** | 0.0 ms | 2249.6 ms | 1748.8 ms | - |
| **Answer Generation Latency (Mean)** | 7382.6 ms | 8381.0 ms | 8274.8 ms | - |
| **Total Query Latency (Mean)** | 7978.0 ms | 10350.1 ms | 9873.5 ms | - |
| **Mean Input Tokens** | 551 | 575 | 591 | - |

---

### Table 4: Statistical Significance Matrix (Wilcoxon Signed-Rank + Holm-Bonferroni)

| Pairwise Comparison | MRR Delta [95% CI] | Wilcoxon $W$ | $p$-value | Adjusted $p_{\text{adj}}$ | Statistically Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Arm B vs. Arm A** (Jina vs. Baseline) | `[+0.0938, +0.1627]` | 807.0 | 2.1309e-11 | **0.0000** | Yes (p < 0.05) |
| **Arm C vs. Arm A** (JEV vs. Baseline)  | `[+0.1472, +0.2227]` | 497.0 | 9.3074e-16 | **0.0000** | Yes (p < 0.05) |
| **Arm C vs. Arm B** (JEV vs. Jina)      | `[+0.0286, +0.0851]` | 570.5 | 2.3188e-04 | **0.0002** | Yes (p < 0.05) |

---

## 4. Generated Visualizations (SVG & High-Res PNG)

The following figures are available in `figures/` in both vector SVG and 300-DPI PNG:
1. `figures/fig1_system_architecture.png` (.svg) — Complete Three-Arm Security RAG Experimental Pipeline Overview.
2. `figures/fig2_ranking_metrics.png` (.svg) — Grouped bar comparison of Recall@1, Recall@5, MRR@10, and nDCG@5.
3. `figures/fig3_latency_vs_accuracy.png` (.svg) — Latency vs. MRR@10 Pareto efficiency frontier.
4. `figures/fig4_answer_correctness.png` (.svg) — Stacked distribution of downstream answer correctness.

---

## 5. Ready-to-Cite Narrative for Paper Sections

### For the Results Section:
> *"As shown in Table \ref{tab:retrieval_ranking_results}, post-retrieval reranking over the frozen hybrid candidate pool ($k=10$) demonstrates distinct ranking behaviors. While the baseline hybrid retriever achieves an MRR@10 of 0.6920, post-retrieval verification with TypeSafe JEV reaches an MRR@10 of 0.8767 and nDCG@5 of 0.8908. Crucially, as reported in Table \ref{tab:latency_telemetry}, JEV achieves this with a mean reranking latency of 1003.3 ms, representing a 27.0\% reduction in latency compared to the hosted neural cross-encoder (Jina, 1373.7 ms), while preserving downstream answer correctness."*
