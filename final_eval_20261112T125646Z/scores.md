# Scores

| Arm | Accuracy | Correct | Wrong | Error |
|---|---:|---:|---:|---:|
| LLM only | 0.0867 | 26 | 274 | 0 |
| Vector RAG | 0.8233 | 247 | 52 | 1 |
| Hybrid RAG | 0.8300 | 249 | 50 | 1 |
| Hybrid RAG + JEV | 0.8133 | 244 | 56 | 0 |
| JEV retrieval | 0.8733 | 262 | 38 | 0 |

C vs D: b=0, c=5, exact two-sided McNemar p=0.0625.
