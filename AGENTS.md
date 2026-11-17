## Project
rag-verify-lab: a local web app that tests whether a claim-verification step improves
hybrid RAG answers for scanner-based security assessment. Read the README for setup.

## Rules
Build complete files. No stubs, no TODO placeholders, except the JEV adapter body, which may raise NotImplementedError until keys are provided.
Never invent results. Every number shown must come from a recorded run.
Never hardcode keys, model names, prices, or IPs. Read them from .env. Embedding and reranking run locally; OpenRouter is used only for answer generation and JEV.
Scans run only after the user checks the authorization box in the UI. Log every scan with its target and authorization. Do not add target restrictions in code.
One heavy job at a time. Use the job queue for scans, container actions, and experiment calls. Never run two concurrently.
Missing keys or models must not crash the app. Mark the affected arm "not configured" and continue.
Keep the UI minimal, use light minimal colours, a clean dashboard.
Run pytest before finishing. Report any failing test; do not delete it.
Ask before adding a dependency not listed in requirements.txt.
Keep changes small and scoped to the task requested.

## Style
- Python 3.11+, type hints on public functions, small modules.
- No frameworks on the frontend.
- Explain decisions briefly in the final message, not in code comments.