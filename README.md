# AI Network Anomaly Detection Platform

A defensive, research-oriented platform for analysing network-flow telemetry. It will combine supervised classification for known attack classes with anomaly detection for unusual, low-confidence behaviour.

## Current stage: data pipeline

The completed increments establish the repository, canonical flow contract, deterministic hybrid risk-decision engine, and a CSV validation pipeline. The project deliberately does **not** claim trained-model capability yet.

The engine consumes model signals (anomaly score and known-class confidence) plus safe contextual signals. This lets us validate the operational decision contract before building the data and training pipeline.

## Delivery sequence

1. **Foundation (complete):** repository layout, feature schema, hybrid decision contract, health endpoint, and tests.
2. **Data pipeline (complete):** dataset provenance template, CICIDS-style CSV validation, label normalisation, and canonical processed output.
3. **ML baselines:** Logistic Regression, Random Forest, and Isolation Forest with evaluation reports.
4. **Inference API:** load a versioned model artifact and expose validated predictions.
5. **Persistence and alerts:** PostgreSQL models, alert lifecycle, history, and analytics endpoints.
6. **Dashboard:** React + TypeScript interface for overview, alerts, analysis, and model metrics.
7. **Advanced capabilities:** explainability, authentication/auditing, Docker Compose, and authorized lab-only Zeek/WebSocket streaming.

## Repository layout

```text
backend/       FastAPI service and hybrid risk engine
ml/            Training and evaluation code (next phase)
data/          Local-only raw/processed datasets and versioned metadata
docs/          Architecture, data dictionary, experiment log, and model card
tests/         Pure-Python unit tests for decision logic
```

## Run the foundation API

Create a Python 3.11+ environment, install the backend requirements, then start the service:

```powershell
python -m pip install -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload
```

Open `http://127.0.0.1:8000/docs` to inspect the API. The initial endpoints are `GET /api/v1/health` and `POST /api/v1/decisions/preview`.

## Verify

```powershell
python -m unittest discover -s tests -v
```

To exercise the CSV pipeline on the safe included sample, see `docs/data-pipeline.md`.

## Safety and scope

This is a defensive monitoring and research prototype. It accepts only authorized benchmark data and authorized lab telemetry. It does not inspect or execute uploaded content, conduct offensive actions, or promise zero-day detection.
