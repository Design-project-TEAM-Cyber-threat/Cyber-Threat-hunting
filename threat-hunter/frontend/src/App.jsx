import { useEffect, useState } from "react";
import { api } from "./api.js";
import { formatDateTime } from "./format.js";
import { useResource } from "./useResource.js";
import AlertDetail from "./components/AlertDetail.jsx";
import Overview from "./components/Overview.jsx";
import RecentAlerts, { PAGE_SIZE } from "./components/RecentAlerts.jsx";
import RiskDistribution from "./components/RiskDistribution.jsx";
import { BackendDown, SafetyBanner, isUnavailable } from "./components/Notices.jsx";

export default function App() {
  const [filters, setFilters] = useState({ level: "", ordering: "newest", page: 1 });
  const [selectedId, setSelectedId] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const summary = useResource(() => api.getSummary(), []);
  const alerts = useResource(
    () => api.getAlerts({ page: filters.page, pageSize: PAGE_SIZE, level: filters.level, ordering: filters.ordering }),
    [filters.page, filters.level, filters.ordering],
  );
  const detail = useResource(() => api.getAlert(selectedId), [selectedId], selectedId !== null);

  const refreshing = summary.loading || alerts.loading;
  const offline = isUnavailable(summary.error) || isUnavailable(alerts.error) || isUnavailable(detail.error);

  useEffect(() => {
    if (!summary.loading && !alerts.loading && !summary.error && !alerts.error) setLastUpdated(new Date().toISOString());
  }, [summary.loading, alerts.loading, summary.error, alerts.error]);

  const refresh = () => {
    summary.reload();
    alerts.reload();
  };
  const status = offline ? "offline" : summary.data ? "online" : "connecting";

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-inner">
          <div>
            <h1>Threat Hunting Dashboard</h1>
            <p>AI-driven anomaly detection prototype · CICIDS2017 network flows</p>
          </div>
          <div className="topbar-actions">
            <span className={`status status-${status}`} role="status">
              <span className="dot" aria-hidden="true" />
              {status === "online" ? "Backend connected" : status === "offline" ? "Backend unreachable" : "Connecting…"}
            </span>
            {lastUpdated && <span className="updated">Updated {formatDateTime(lastUpdated)}</span>}
            <button type="button" className="btn btn-primary" onClick={refresh} disabled={refreshing}>
              {refreshing ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
      </header>

      <main className="content">
        <SafetyBanner />

        {offline && <BackendDown baseUrl={api.baseUrl} onRetry={refresh} retrying={refreshing} />}

        <section className="card" aria-labelledby="h-overview">
          <h2 id="h-overview">Overview</h2>
          <Overview summary={summary.data} loading={summary.loading} error={summary.error} />
        </section>

        <section className="card" aria-labelledby="h-dist">
          <h2 id="h-dist">Risk distribution</h2>
          <RiskDistribution summary={summary.data} loading={summary.loading} error={summary.error} />
        </section>

        <div className="split">
          <section className="card" aria-labelledby="h-alerts">
            <h2 id="h-alerts">Recent alerts</h2>
            <RecentAlerts
              data={alerts.data}
              loading={alerts.loading}
              error={alerts.error}
              filters={filters}
              onFilters={(patch) => setFilters((f) => ({ ...f, ...patch }))}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onRetry={alerts.reload}
              hasAnyAlerts={(summary.data?.total_alerts || 0) > 0}
            />
          </section>
          <aside className="card detail-card" aria-label="Alert details">
            <AlertDetail
              alertId={selectedId}
              data={detail.data}
              loading={detail.loading}
              error={detail.error}
              onClose={() => setSelectedId(null)}
              onRetry={detail.reload}
            />
          </aside>
        </div>
      </main>

      <footer className="footer">
        Prototype for a college project. Scores indicate unusual behavior for human review; they do not identify attacks or trigger any action.
      </footer>
    </div>
  );
}
