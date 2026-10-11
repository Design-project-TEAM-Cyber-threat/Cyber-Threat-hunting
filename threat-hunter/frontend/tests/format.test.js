import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatNumber, formatScore, formatValue, formatPercent, formatDateTime, formatDrivers,
  featureLabel, formatDirection, formatAutomatedAction, totalPages, levelClass,
} from "../src/format.js";
import { FEATURE_LABELS } from "../src/featureLabels.js";

test("numbers", () => {
  assert.equal(formatNumber(1234567), "1,234,567");
  assert.equal(formatNumber(null), "—");
  assert.equal(formatNumber(undefined), "—");
  assert.equal(formatScore(93.456), "93.5");
  assert.equal(formatScore(null), "—");
  assert.equal(formatPercent(1, 4), "25.0%");
  assert.equal(formatPercent(0, 0), "0%");
});

test("formatValue mirrors the backend's compact numbers", () => {
  assert.equal(formatValue(0), "0");
  assert.equal(formatValue(95.3), "95");
  assert.equal(formatValue(0.00007612), "0.000076");
  assert.equal(formatValue(7.6), "7.6");
  assert.equal(formatValue(98000000), "98,000,000");
  assert.equal(formatValue(null), "—");
});

test("dates are shown only when valid", () => {
  assert.equal(formatDateTime(null), "—");
  assert.equal(formatDateTime("not a date"), "—");
  assert.notEqual(formatDateTime("2026-10-03T10:15:00Z"), "—");
});

test("drivers and feature labels", () => {
  assert.deepEqual(formatDrivers(["anomaly", "deviation"]), ["Anomaly model", "Baseline deviation"]);
  assert.deepEqual(formatDrivers([]), []);
  assert.deepEqual(formatDrivers(undefined), []);
  assert.equal(featureLabel("packets_per_sec"), "Packet rate");
  assert.equal(featureLabel("unknown_feature"), "unknown_feature");
  assert.equal(Object.keys(FEATURE_LABELS).length, 21);
  assert.equal(formatDirection({ magnitude: "far", direction: "higher" }), "far higher");
  assert.equal(formatDirection(null), "");
});

test("automated action shows the API value, 'None' for the current system", () => {
  assert.equal(formatAutomatedAction("none"), "None");
  assert.equal(formatAutomatedAction(undefined), "—");
});

test("paging and level classes", () => {
  assert.equal(totalPages(0, 10), 1);
  assert.equal(totalPages(25, 10), 3);
  assert.equal(totalPages(30, 10), 3);
  assert.equal(levelClass("High"), "level-high");
});
