# Audit for paper: final 300-question experiment

## Scope and method

This audit uses only the recorded final run `final_eval_20261112T125646Z` and
the implementation/configuration files that define its scoring and arms. No
scan, experiment, model/API call, or raw-artifact edit was performed.

The primary question-level source is
[`question_level_results.csv`](./final_eval_20261112T125646Z/tables/question_level_results.csv)
(1,500 rows). Counts were recomputed by question ID and arm. A prediction is
correct only when `valid=True` and its parsed CVE exactly equals the gold CVE;
provider errors are reported separately and count as incorrect for accuracy.
This matches `score_predictions` and `mcnemar_p_value` in
[`final_runner.py`](./rag_verify_lab/eval_final/final_runner.py).

## Recomputed results

| Arm | Correct | Wrong CVE | Blank/invalid | Provider error | Total | Accuracy |
|---|---:|---:|---:|---:|---:|---:|
| LLM only | 26 | 274 | 0 | 0 | 300 | 8.6667% |
| Vector RAG | 247 | 51 | 1 | 1 | 300 | 82.3333% |
| Hybrid RAG (C) | 249 | 50 | 0 | 1 | 300 | 83.0000% |
| Hybrid + JEV (D) | 244 | 25 | 31 | 0 | 300 | 81.3333% |
| JEV retrieval (E) | 262 | 38 | 0 | 0 | 300 | 87.3333% |

The Vector RAG split is 247 correct, 51 wrong CVEs, 1 blank/invalid response,
and 1 provider error. The blank/invalid row is Q-0594; the provider error is a
different question. All four outcome categories are mutually exclusive and
sum to 300.

The recorded Wilson intervals and aggregate values in
[`stats.json`](./final_eval_20261112T125646Z/stats.json) agree with these
recomputed counts. Accuracy is correct/300.

## C versus D paired audit

Pairing by question ID gives five discordant questions:

| Question | Gold CVE | C answer | D answer | Outcome |
|---|---|---|---|---|
| Q-0426 | CVE-2020-14882 | CVE-2020-14882 | blank | C only correct |
| Q-0442 | CVE-2020-1938 | CVE-2020-1938 | blank | C only correct |
| Q-0476 | CVE-2020-6418 | CVE-2020-6418 | blank | C only correct |
| Q-0569 | CVE-2021-30563 | CVE-2021-30563 | blank | C only correct |
| Q-0600 | CVE-2021-35042 | CVE-2021-35042 | blank | C only correct |

Thus `b = 0` (D correct/C wrong), `c = 5` (C correct/D wrong), and the exact
two-sided McNemar p-value is **0.0625**. The accuracy difference D-C is
**-1.6667 percentage points**. There is no paired evidence here that D
improved C; the observed direction favors C, but the exact test is not below
0.05.

## What Arm D actually did

The final runner first reuses Arm C's answer, parses the first study-valid CVE,
then supplies the parsed C answer and the Hybrid top-five CVE candidates to
`JEVClient.select_candidate`. It blanks the answer unless the selected CVE
exactly equals the C answer; this is the `hybrid_jev` branch in
[`final_runner.py`](./rag_verify_lab/eval_final/final_runner.py) and the
selection contract in [`jev.py`](./rag_verify_lab/verify/jev.py).

The saved rows show:

- 299 JEV calls and 1 row with zero JEV calls (the C provider-error question
  Q-0481); there are no recorded D provider errors.
- 244 D answers are correct.
- 25 nonblank D answers are wrong; these are accepted by the exact-match gate
  but do not match the gold CVE.
- 31 D answers are blank/invalid. Five are the C-correct/D-wrong paired
  disagreements above; the remaining 26 occur where C was already wrong.
- There are no D-correct/C-wrong rows.

The 31 blank rows are classified in `failure_cases.csv` as
`unparseable_or_withheld`. The recorded output does not preserve a separate
JEV decision label, citation score, or raw response, so it is not possible to
verify whether each blank was caused by an explicit JEV rejection, candidate
selection mismatch, or another parsing-level event. The code path verifies the
exact-match rule, but not a more granular causal explanation for every blank.

For C, `failure_cases.csv` contains 50 `wrong_cve` rows and one
`provider_error` row (Q-0481, `Connection error.`). C's wrong-CVE failures
include both cases where the gold was retrieved and cases marked
`not_found@50`; those are recorded retrieval outcomes, not inferred causes.

## Arm E is separate

Arm E is not verification of a generated Hybrid answer. The final runner sends
up to 20 BM25-derived CVE candidates to JEV and directly records JEV's selected
CVE; it does not call the answer model in this final path. E therefore measures
candidate selection, not the D gate. E achieved 262/300 (87.3333%) and had 38
wrong-CVE rows, all classified as `wrong_cve`; it had 300 JEV calls and zero
recorded answer-model calls/tokens in
[`latency_usage_cost_by_arm.csv`](./final_eval_20261112T125646Z/tables/latency_usage_cost_by_arm.csv).

## Calls, tokens, latency, and cost

The recorded usage table reports:

| Arm | Answer calls | JEV calls | Recorded LLM tokens | Median ms | P95 ms |
|---|---:|---:|---:|---:|---:|
| LLM only | 300 | 0 | 63,223 | 1,103.987 | 2,163.503 |
| Vector RAG | 299 | 0 | 231,819 input / 14,641 output tokens | 2,545.492 | 5,047.539 |
| Hybrid RAG | 299 | 0 | 236,144 input / 15,057 output tokens; error row has no usage | 2,586.952 | 5,131.536 |
| Hybrid + JEV | 0 new answer calls; C answer reused | 299 | 0 in D row | 800.870 | 1,789.969 |
| JEV retrieval | 0 | 300 | 0 | 961.994 | 2,299.178 |

The saved artifact reports Hybrid C's recorded answer-token totals as
236,144 input and 15,057 output tokens; one provider-error row lacks usage. D
reuses C's generated answers, so its verification latency is not a fresh
end-to-end C-plus-D latency.

[`observed_costs.csv`](./final_eval_20261112T125646Z/tables/observed_costs.csv)
records **$0.09 observed JEV spend for 599 calls combined** (299 D + 300 E).
No per-arm invoice split or Groq invoice was recorded, so arm-level observed
dollar costs cannot be computed. All run-configured arm costs remain
`unknown`.

GPT-6 Luna was not used. Any Luna-rate calculation is a hypothetical estimate,
not incurred spend. The existing estimate of $0.0311 for D uses 236,144 input
and 15,057 output tokens at the stated reference rates and excludes JEV spend.
It must not be presented as an experiment cost.

## Inconsistencies and unresolved evidence

1. `run_config.json` contains an inherited `answer_calls: 300` entry for E,
   while the final predictions, implementation path, and usage table show
   0 answer-model calls and 300 JEV calls. The audit uses the row-level and
   implementation evidence for E and treats the config field as inconsistent.
2. The local artifacts contain a user-reported aggregate JEV billing amount but
   no invoice or per-arm allocation. The $0.09 total is recorded, not
   independently reconciled here.
3. Raw JEV responses, selection labels, and citation probabilities are not
   included in the final artifacts. D's exact-match behavior is verifiable,
   but the causal reason for each withheld row is not.
4. The source dataset's `blind_audit` is recorded as not run because no
   predictor was authorized/configured; the 30-item hand check is recorded as
   passed. This limits claims about independent benchmark validation.
5. The existing cost-versus-accuracy image is explicitly not a monetary result
   because configured prices are unknown; use the chart-ready CSVs for
   accuracy and calls/latency instead.

## Main verified conclusion

On this frozen 300-question scanner-oriented CVE benchmark and this exact
configuration, Arm D did **not** improve Arm C: it was lower by five correct
questions (81.33% vs 83.00%), with all paired disagreements favoring C and
exact McNemar p=0.0625. Arm E was higher (87.33%), but it is a separate JEV
candidate-selection arm and is not evidence that verification improves Hybrid
RAG. These conclusions do not generalize to RAG systems, datasets, or model
configurations beyond the recorded run.
