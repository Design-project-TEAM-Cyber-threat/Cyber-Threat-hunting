import { formatDateTime, formatDrivers, formatScore, levelClass, totalPages } from "../format.js";
import { ErrorNotice, Loading, isUnavailable } from "./Notices.jsx";

export const PAGE_SIZE = 10;

export default function RecentAlerts({ data, loading, error, filters, onFilters, selectedId, onSelect, onRetry, hasAnyAlerts }) {
  const pages = totalPages(data?.count, PAGE_SIZE);
  const rows = data?.results || [];

  return (
    <div>
      <div className="toolbar">
        <label>
          Level
          <select value={filters.level} onChange={(e) => onFilters({ level: e.target.value, page: 1 })}>
            <option value="">All alerts</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>
        </label>
        <label>
          Sort by
          <select value={filters.ordering} onChange={(e) => onFilters({ ordering: e.target.value, page: 1 })}>
            <option value="newest">Newest first</option>
            <option value="risk">Highest risk first</option>
          </select>
        </label>
        <span className="toolbar-count" aria-live="polite">{data ? `${data.count} alert${data.count === 1 ? "" : "s"}` : ""}</span>
      </div>

      {error && !isUnavailable(error) && <ErrorNotice title="Could not load alerts" error={error} onRetry={onRetry} />}
      {!data && loading && <Loading label="Loading alerts…" />}
      {!data && !loading && isUnavailable(error) && <p className="muted">Alerts unavailable while the backend is down.</p>}

      {data && rows.length === 0 && (
        <div className="empty">
          {hasAnyAlerts || filters.level ? (
            <>
              <strong>No alerts match these filters.</strong>
              <p>Choose “All alerts” to see everything stored.</p>
            </>
          ) : (
            <>
              <strong>No alerts yet.</strong>
              <p>Alerts appear here when a scored flow reaches Medium or High risk. Send flows with <code>POST /api/score/</code> or run <code>python backend\demo_api.py</code>.</p>
            </>
          )}
        </div>
      )}

      {rows.length > 0 && (
        <div className={`table-wrap ${loading ? "is-loading" : ""}`}>
          <table className="alerts">
            <thead>
              <tr><th>ID</th><th>Risk level</th><th className="num">Risk score</th><th>Port / service</th><th>Driver</th><th>Time</th></tr>
            </thead>
            <tbody>
              {rows.map((a) => {
                const drivers = formatDrivers(a.drivers);
                return (
                  <tr
                    key={a.id}
                    className={a.id === selectedId ? "selected" : ""}
                    tabIndex={0}
                    onClick={() => onSelect(a.id)}
                    onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(a.id); } }}
                    aria-selected={a.id === selectedId}
                  >
                    <td>#{a.id}</td>
                    <td><span className={`badge ${levelClass(a.risk_level)}`}>{a.risk_level}</span></td>
                    <td className="num">
                      <span className="score">{formatScore(a.risk_score)}</span>
                      <span className="meter" aria-hidden="true"><span className={`meter-fill ${levelClass(a.risk_level)}`} style={{ width: `${Math.min(100, a.risk_score)}%` }} /></span>
                    </td>
                    <td>{a.service || `port ${a.destination_port}`}</td>
                    <td>{drivers.length ? drivers.join(" + ") : "—"}</td>
                    <td className="nowrap" title={a.created_at}>{formatDateTime(a.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {data && data.count > PAGE_SIZE && (
        <div className="pager">
          <button type="button" className="btn btn-small" disabled={!data.previous || loading} onClick={() => onFilters({ page: filters.page - 1 })}>← Previous</button>
          <span>Page {filters.page} of {pages}</span>
          <button type="button" className="btn btn-small" disabled={!data.next || loading} onClick={() => onFilters({ page: filters.page + 1 })}>Next →</button>
        </div>
      )}
    </div>
  );
}
