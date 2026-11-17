# Hard-set retrieval evaluation

- Corpus SHA-256: `8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc`
- Index version: `68e2ecad34e25474fcf5d50c0b14fdcc7b8bf92ea8d4ec5d2347a08e7361a3ea`
- Embedding model: `BAAI/bge-base-en-v1.5`
- Embedding revision: `a5beb1e3e68b9ab74eb54cfd186867f64f240e1a`
- Reranker model: `BAAI/bge-reranker-v2-m3`
- Reranker revision: `953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e`
- Questions: 25
- Bootstrap: 1,000 resamples, seed 42; percentile 95% intervals
- Reranker check: confirmed hybrid fusion top 20 were reranked and final order was selected from reranker scores. No code change was required.
- JEV-retrieval: one System One request per question; 20 BM25 candidates scored per request.
- Precision@5: capped at 0.2 with one gold CVE per question.

- Date: `2026-11-06T21:51:53.804192+00:00`
- JEV calls: 25

| configuration | recall@10 | MRR | nDCG@10 |
|---|---:|---:|---:|
| dense only | 1.000000 [1.000000, 1.000000] | 0.795714 [0.671429, 0.900000] | 0.847221 [0.753493, 0.926186] |
| hybrid | 1.000000 [1.000000, 1.000000] | 0.861333 [0.757267, 0.953333] | 0.896423 [0.817834, 0.965237] |
| hybrid + reranker | 1.000000 [1.000000, 1.000000] | 0.794667 [0.663967, 0.900167] | 0.846383 [0.746817, 0.926280] |
| jev-retrieval | 1.000000 [1.000000, 1.000000] | 0.840000 [0.740000, 0.940000] | 0.881898 [0.808083, 0.955712] |
