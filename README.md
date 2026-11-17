# rag-verify-lab

`rag-verify-lab` is a local FastAPI dashboard for testing whether claim verification improves hybrid RAG answers for scanner-based security assessment. It stores scans, questions, experiment results, and job status in SQLite.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Fill in the model/API values in `.env`. Blank model values intentionally leave the corresponding arm as **not configured**. Docker must be running for image and sweep actions. Start with `bkimminich/juice-shop`; Metasploitable 2 is heavy and should run alone with a wide Nmap range.

Run:

```powershell
python -m rag_verify_lab.app
```

Open http://localhost:8000. Enter a valid IP, hostname, or `/24`-to-`/32` CIDR and confirm that you are authorized to scan it.

## Testing

```powershell
pytest
```

Retrieval models are local sentence-transformers models. OpenRouter is used only
for answer generation and JEV. Configure model names and revisions in `.env`,
then run these commands:

```powershell
python -m rag_verify_lab.models download
python -m rag_verify_lab.cli build-index
python -m rag_verify_lab.eval retrieval
python -m rag_verify_lab.cli arms --question 1 --arms hybrid_rag,jev_retrieval
```

The evaluation writes `data/eval/<index_version>/retrieval_eval.csv` and
`retrieval_eval.md`. Local retrieval timings are not billed hosted cost.

The app uses one worker thread for scans, container operations, sweeps, pulls, and experiments. Configuration snapshots mask secrets, and prices remain unknown when the matching environment value is blank.

## JEV contract to verify

The JEV adapter uses TypeSafe's System One API:
`POST https://api.typesafe.ai/v1/systemone`. It sends `JEV_MODEL`, bearer
authentication, a claim/evidence `state`, and named `choice`/`noul` questions.
The response contains typed answers under `answers`; the adapter maps the
support choice and citation probability to the experiment's judgment fields.
The dashboard's **Test JEV** button and `GET /api/jev/health` use the same
documented endpoint and refuse JEV experiments when configuration,
authentication, reachability, or model acceptance fails.