# Dashboard (Step 8): React + Vite

```powershell
npm install        # react, react-dom, vite, @vitejs/plugin-react
npm run dev        # http://localhost:5173   (Django must be running on http://127.0.0.1:8000)
npm test           # unit tests for the API client and formatting helpers (Node 18+)
npm run build      # production build into dist/
```

**How it connects to Django:** the browser calls same-origin `/api/...`; the Vite dev server (`vite.config.js`)
forwards `/api` to `http://127.0.0.1:8000`. If Django is down the proxy answers 502 and the dashboard shows a
"Backend unavailable" message with the start command. To call the API directly instead, copy `.env.example` to
`.env` and set `VITE_API_BASE_URL` (Django already allows CORS from localhost:5173).

**Data used (read-only GET requests):** `/api/summary/`, `/api/alerts/` (filters, sorting, paging), `/api/alerts/<id>/`.
Nothing is invented: counts, scores, evidence, explanations, responses and timestamps come from the API.
The only text added by the dashboard is the fixed safety notice ("Unusual behavior is not proof of a malicious attack.")
and display labels for the 21 feature names.
