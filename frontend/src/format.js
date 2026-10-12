// Small display helpers. They only format values that the API returned.
import { FEATURE_LABELS } from "./featureLabels.js";

export const LEVELS = ["Low", "Medium", "High"];

export function formatNumber(n) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return "—";
  return Number(n).toLocaleString("en-US");
}

export function formatScore(n, digits = 1) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return "—";
  return Number(n).toFixed(digits);
}

// Same idea as the backend explanation text: compact numbers with sensible precision.
export function formatValue(v) {
  if (v === null || v === undefined || Number.isNaN(Number(v))) return "—";
  const x = Number(v);
  if (x === 0) return "0";
  const a = Math.abs(x);
  if (a >= 1000) return Math.round(x).toLocaleString("en-US");
  if (a >= 10) return String(Math.round(x));
  return String(Number(x.toPrecision(2)));
}

export function formatPercent(part, total, digits = 1) {
  if (!total) return "0%";
  return `${((part / total) * 100).toFixed(digits)}%`;
}

export function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

const DRIVER_LABELS = { anomaly: "Anomaly model", deviation: "Baseline deviation" };

export function formatDrivers(drivers) {
  if (!Array.isArray(drivers) || drivers.length === 0) return [];
  return drivers.map((d) => DRIVER_LABELS[d] || String(d));
}

export function featureLabel(name) {
  return FEATURE_LABELS[name] || name;
}

export function formatDirection(f) {
  if (!f || !f.direction) return "";
  return [f.magnitude, f.direction].filter(Boolean).join(" ");
}

export function formatAutomatedAction(value) {
  if (value === null || value === undefined || value === "") return "—";
  const s = String(value);
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function totalPages(count, pageSize) {
  if (!count || !pageSize) return 1;
  return Math.max(1, Math.ceil(count / pageSize));
}

export function levelClass(level) {
  return `level-${String(level || "").toLowerCase()}`;
}
