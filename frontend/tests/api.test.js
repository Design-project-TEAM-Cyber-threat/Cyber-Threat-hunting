import { test } from "node:test";
import assert from "node:assert/strict";
import { createApi, ApiError, BackendUnavailableError, buildQuery } from "../src/api.js";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const mk = (impl, extra = {}) => createApi({ baseUrl: "/api/", fetchImpl: impl, ...extra });

test("buildQuery skips empty values and encodes the rest", () => {
  assert.equal(buildQuery({}), "");
  assert.equal(buildQuery({ a: "", b: undefined, c: null }), "");
  assert.equal(buildQuery({ level: "High", page: 2, q: "a b" }), "?level=High&page=2&q=a%20b");
});

test("getSummary calls /api/summary/ with GET and returns JSON", async () => {
  let seen;
  const api = mk(async (url, opts) => {
    seen = { url, opts };
    return json({ total_flows: 10 });
  });
  assert.deepEqual(await api.getSummary(), { total_flows: 10 });
  assert.equal(seen.url, "/api/summary/");
  assert.equal(seen.opts.method, undefined); // default GET: the client never sends write requests
});

test("getAlerts maps options to the API's query names", async () => {
  let url;
  const api = mk(async (u) => ((url = u), json({ count: 0, results: [] })));
  await api.getAlerts({ page: 2, pageSize: 10, level: "High", ordering: "risk" });
  assert.equal(url, "/api/alerts/?page=2&page_size=10&level=High&ordering=risk");
  await api.getAlerts({ page: 1, pageSize: 10, level: "", ordering: "newest" });
  assert.equal(url, "/api/alerts/?page=1&page_size=10&ordering=newest");
});

test("getModelMetrics calls /api/model-metrics/ and returns the saved JSON", async () => {
  let seen;
  const body = { accuracy: 0.91, precision: 0.82, recall: 0.77, f1_score: 0.794, roc_auc: 0.88 };
  const api = mk(async (url, opts) => {
    seen = { url, opts };
    return json(body);
  });
  assert.deepEqual(await api.getModelMetrics(), body);
  assert.equal(seen.url, "/api/model-metrics/");
  assert.equal(seen.opts.method, undefined);
});

test("a missing metrics file is an ApiError with the server message", async () => {
  const api = mk(async () => json({ error: "Model metrics have not been calculated." }, 404));
  await assert.rejects(api.getModelMetrics(), (e) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 404);
    assert.equal(e.message, "Model metrics have not been calculated.");
    return true;
  });
});

test("getAlert calls the detail URL", async () => {
  let url;
  const api = mk(async (u) => ((url = u), json({ id: 7 })));
  assert.equal((await api.getAlert(7)).id, 7);
  assert.equal(url, "/api/alerts/7/");
});

test("HTTP 4xx with a JSON error becomes ApiError with the server's message and status", async () => {
  const api = mk(async () => json({ error: "Invalid request.", details: { level: "bad" } }, 400));
  await assert.rejects(api.getAlerts({ level: "x" }), (e) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 400);
    assert.equal(e.message, "Invalid request.");
    assert.deepEqual(e.details, { level: "bad" });
    return true;
  });
  const nf = mk(async () => json({ detail: "Not found." }, 404));
  await assert.rejects(nf.getAlert(1), (e) => e instanceof ApiError && e.status === 404 && e.message === "Not found.");
});

test("a Django 500 with a JSON body is an ApiError, not 'backend unavailable'", async () => {
  const api = mk(async () => json({ error: "boom" }, 500));
  await assert.rejects(api.getSummary(), (e) => e instanceof ApiError && e.status === 500);
});

test("502/503/504 and a bodiless 500 (dev-proxy failure) mean backend unavailable", async () => {
  for (const status of [502, 503, 504]) {
    const api = mk(async () => json({ error: "backend_unavailable" }, status));
    await assert.rejects(api.getSummary(), (e) => e instanceof BackendUnavailableError && e.status === status);
  }
  const bare = mk(async () => new Response("", { status: 500, headers: { "Content-Type": "text/plain" } }));
  await assert.rejects(bare.getSummary(), (e) => e instanceof BackendUnavailableError);
});

test("a network failure (fetch rejects) means backend unavailable", async () => {
  const api = mk(async () => {
    throw new TypeError("Failed to fetch");
  });
  await assert.rejects(api.getSummary(), (e) => e instanceof BackendUnavailableError && /Cannot reach/.test(e.message));
});

test("a request that never answers times out as backend unavailable (no hanging)", async () => {
  const api = mk(
    (url, { signal }) =>
      new Promise((_, reject) => {
        signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      }),
    { timeoutMs: 50 },
  );
  const t0 = Date.now();
  await assert.rejects(api.getSummary(), (e) => e instanceof BackendUnavailableError && /did not respond/.test(e.message));
  assert.ok(Date.now() - t0 < 2000);
});

test("a 200 response that is not JSON is reported, not silently accepted", async () => {
  const api = mk(async () => new Response("<html>hi</html>", { status: 200 }));
  await assert.rejects(api.getSummary(), (e) => e instanceof ApiError);
});
