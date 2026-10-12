// Thin client for the existing Django REST API (Step 7). Read-only: it only issues GET requests.

export class ApiError extends Error {
  constructor(message, { status, details } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

export class BackendUnavailableError extends Error {
  constructor(message, { cause, status } = {}) {
    super(message);
    this.name = "BackendUnavailableError";
    this.cause = cause;
    this.status = status;
  }
}

export function buildQuery(params = {}) {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  return parts.length ? `?${parts.join("&")}` : "";
}

export function createApi({ baseUrl = "/api", fetchImpl, timeoutMs = 15000 } = {}) {
  const base = baseUrl.replace(/\/+$/, "");
  const doFetch = fetchImpl ?? ((...args) => globalThis.fetch(...args));

  async function get(path, params) {
    const url = `${base}${path}${buildQuery(params)}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    let text;
    try {
      response = await doFetch(url, { headers: { Accept: "application/json" }, signal: controller.signal });
      text = await response.text();
    } catch (err) {
      if (err && err.name === "AbortError") {
        throw new BackendUnavailableError(`The API did not respond within ${Math.round(timeoutMs / 1000)} seconds.`, { cause: err });
      }
      throw new BackendUnavailableError("Cannot reach the backend API.", { cause: err });
    } finally {
      clearTimeout(timer);
    }

    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
    }

    const { status } = response;
    // 502/503/504, or a bodiless 500 from the dev proxy, mean "the backend is not answering".
    if ([502, 503, 504].includes(status) || (status === 500 && body === null && !/html/i.test(text || ""))) {
      throw new BackendUnavailableError("The backend API is not responding.", { status });
    }
    if (!response.ok) {
      const message = (body && (body.error || body.detail)) || `The API returned an error (HTTP ${status}).`;
      throw new ApiError(typeof message === "string" ? message : JSON.stringify(message), {
        status,
        details: body && body.details,
      });
    }
    if (body === null) {
      throw new ApiError("The API returned an unexpected (non-JSON) response.", { status });
    }
    return body;
  }

  return {
    baseUrl: base,
    getSummary: () => get("/summary/"),
    getAlerts: ({ page, pageSize, level, ordering } = {}) =>
      get("/alerts/", { page, page_size: pageSize, level, ordering }),
    getAlert: (id) => get(`/alerts/${encodeURIComponent(id)}/`),
  };
}

const configuredBase =
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_API_BASE_URL) || "/api";

export const api = createApi({ baseUrl: configuredBase });
