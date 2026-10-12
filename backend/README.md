# Backend (Django REST + SQLite)

```powershell
pip install -r ../requirements.txt
python manage.py makemigrations alerts
python manage.py migrate
python manage.py test            # API tests (synthetic models, runs in seconds)
python manage.py runserver       # http://127.0.0.1:8000/api/
python demo_api.py            # synthetic demo flows
python demo_api.py C:\path\to\Friday-WorkingHours-Afternoon-DDos_pcap_ISCX.csv 500
```
See ../README.md for full Windows setup. Model files must exist in `../ml/artifacts/` (created by `ml/train_anomaly.py` and `ml/evaluate_baseline.py` / `ml/evaluate_risk.py`).

| Method | URL | Purpose |
|---|---|---|
| GET | /api/health/ | liveness |
| POST | /api/score/ | `{"flows":[raw CICIDS2017 fields...], "learn": false}` - score, risk, explain, persist |
| GET | /api/alerts/ | list Medium/High alerts (`level`, `port`, `min_risk`, `ordering=newest|risk`, `page`, `page_size`) |
| GET | /api/alerts/<id>/ | alert exactly as stored at detection time |
| GET | /api/summary/ | counts for the dashboard |

There are no endpoints that block, isolate, quarantine or disable anything. Alerts are immutable;
their explanations are stored when generated and never recomputed from the current baseline.
`learn=true` lets low-risk Normal flows move the in-memory baseline (alerts never do).
The API has no authentication (demo only).
