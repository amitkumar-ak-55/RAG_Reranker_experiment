# Scores

| Arm | Accuracy | Correct | Wrong | Invalid | Error |
|---|---:|---:|---:|---:|---:|
| LLM only | 0.0733 | 22 | 254 | 1 | 23 |
| Vector RAG | 0.0467 | 14 | 229 | 34 | 23 |
| Hybrid RAG | 0.0700 | 21 | 231 | 26 | 22 |
| Hybrid RAG + JEV | 0.0200 | 6 | 40 | 254 | 0 |
| JEV retrieval | 0.0433 | 13 | 213 | 26 | 48 |

C vs D: b=0, c=15, exact two-sided McNemar p=6.1035156e-05.
