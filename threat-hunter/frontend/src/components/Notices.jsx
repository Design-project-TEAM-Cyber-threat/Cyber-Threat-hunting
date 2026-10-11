import { ApiError, BackendUnavailableError } from "../api.js";

export function SafetyBanner() {
  return (
    <section className="safety" aria-label="How to read this dashboard">
      <p className="safety-main">Unusual behavior is not proof of a malicious attack.</p>
      <p className="safety-sub">
        Alerts are triage priorities for a person to review. <strong>Automated action: None</strong> — this
        system does not block, isolate or disable anything.
      </p>
    </section>
  );
}

export function BackendDown({ baseUrl, onRetry, retrying }) {
  return (
    <div className="notice notice-error" role="alert">
      <h2>Backend unavailable</h2>
      <p>The dashboard could not reach the Django API ({baseUrl}). Nothing is wrong with your data; the server just is not answering.</p>
      <p>Start it in a separate terminal:</p>
      <pre>cd backend{"\n"}python manage.py runserver</pre>
      <button type="button" className="btn" onClick={onRetry} disabled={retrying}>
        {retrying ? "Retrying…" : "Retry"}
      </button>
    </div>
  );
}

export function ErrorNotice({ title, error, onRetry }) {
  const status = error instanceof ApiError && error.status ? ` (HTTP ${error.status})` : "";
  return (
    <div className="notice notice-warn" role="alert">
      <strong>{title}{status}</strong>
      <p>{error?.message || "Something went wrong."}</p>
      {onRetry && (
        <button type="button" className="btn btn-small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Loading({ label = "Loading…" }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function isUnavailable(error) {
  return error instanceof BackendUnavailableError;
}
