# AI-Driven Cyber Threat Hunting Prototype (college project, ~50% prototype)

Pipeline: CICIDS2017 flows -> preprocessing -> behavioral features -> Isolation Forest -> Normal/Anomaly
-> adaptive per-service baseline -> contextual risk score -> explainable alert -> advisory response
-> REST API (Django + SQLite) -> React + Vite dashboard (Step 8).

## Honest scope (use this wording in your report)
* Isolation Forest scores how **unusual** a flow is. An anomaly is **not** an attack, and the system does not
  claim to detect every (or any specific) zero-day attack. It can miss attacks that look normal per flow
  (on CICIDS2017: PortScan, brute-force and web attacks were mostly not flagged) and flags benign rare traffic.
* The risk score (0-100) is separate from the anomaly score and the baseline deviation. It treats them as weak
  evidence plus service/port context. On the real data its High level is mostly benign traffic.
* "Adaptive" = the per-service baseline follows legitimate change using only low-risk flows, with guards
  (slow window, drift limit, surge freeze). CICIDS2017 has no host addresses or timestamps, so baselines are
  per destination service, replayed in capture-day order.
* Nothing blocks, isolates or disables anything. Responses are advisory text only.

## Project layout
```
ml/            Steps 1-6 and the detection pipeline (preprocessing, features, anomaly, baseline, risk, explain, detection)
ml/artifacts/  trained models: isolation_forest, adaptive_baseline, risk_scorer (+ sample_alerts.json)
backend/       Step 7: Django REST API (config/, alerts/, manage.py, demo_api.py)
frontend/      Step 8: React + Vite dashboard (reads the Django API; read-only)
tests/         framework-free tests for Steps 1-7 core
data/          sample_cicids.csv (tiny synthetic file used by tests); put the real CICIDS2017 CSVs here
run_all_tests.py
```

## Run Step 7 on Windows (PowerShell)
Use 64-bit Python 3.11 or 3.12 (the pinned numpy/pandas versions need it). From the `threat-hunter` folder:
```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked:  Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt

python run_all_tests.py             # Steps 1-7 core tests (no Django needed)

cd backend
python manage.py makemigrations alerts
python manage.py migrate
python manage.py test               # Django API tests
python manage.py runserver          # http://127.0.0.1:8000/api/health/
```
In a second PowerShell window (venv activated), from `threat-hunter\backend`:
```powershell
python demo_api.py                                        # synthetic demo flows, no dataset needed
python demo_api.py C:\path\to\Friday-WorkingHours-Afternoon-DDos_pcap_ISCX.csv 500   # real flows
```

## Run the dashboard (Step 8)
Needs Node.js 18 or newer (https://nodejs.org). Keep the Django server from above running, then in a NEW terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173**. The dashboard shows only data stored in the API. If it is empty, send flows first
(`python backend\demo_api.py` with a CICIDS2017 CSV path, or with no argument for synthetic demo flows).
`npm test` runs the dashboard's unit tests. Details: `frontend/README.md`.

## API
| Method | URL | Purpose |
|---|---|---|
| GET | /api/health/ | liveness |
| POST | /api/score/ | `{"flows":[raw CICIDS2017 fields...], "learn": false}` - score, risk, explain, persist |
| GET | /api/alerts/ | Medium/High alerts (`level`, `port`, `min_risk`, `ordering=newest\|risk`, `page`, `page_size`) |
| GET | /api/alerts/<id>/ | alert exactly as stored at detection time |
| GET | /api/summary/ | counts for the dashboard |

Alerts are immutable and store the explanation generated at detection time; they are never recomputed from
the current baseline. The API has no authentication (demo only) and no destructive endpoints.

## Retraining on the real CICIDS2017 CSVs (optional)
Download the "MachineLearningCVE" CSVs into `data\` (about 2.8M flows; ~4 GB RAM is enough). From the project root:
```powershell
python ml\inspect_dataset.py data                     # Step 1 report on the real files
python ml\train_anomaly.py data data\processed\features.joblib      # trains + evaluates Isolation Forest
python ml\evaluate_baseline.py data\processed\features.joblib       # baseline comparison, saves baseline
python ml\evaluate_risk.py data\processed\features.joblib data\processed\stream_results.joblib
python ml\run_explanations.py data\processed\features.joblib        # sample explained alerts
```
The first command that needs features builds and caches them. Restart the server after retraining.

## Known limitations
* `idle_mean_s` is zero for ~77% of flows, so it dominates many explanations (left unchanged on purpose).
* The dashboard shows what the API stores; it adds no data, no auto-refresh and no actions.
* Saved models are pickles tied to the pinned library versions in requirements.txt.
