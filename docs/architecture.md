# Architecture: foundation

```text
Authorized flow dataset
        |
        v
Reproducible preprocessing (next phase)
        |
        v
Classifier + anomaly detector (next phase)
        |
        v
Hybrid risk decision policy (implemented)
        |
        v
FastAPI decision contract (implemented)
```

The training workflow and online API are intentionally separate. The API will load an approved, versioned artifact set; it will never retrain due to a dashboard request.
