"""
API tests (run from backend/ with:  python manage.py test).
They use a small synthetic world (ml/synthetic_world.py) so they run in seconds.
"""
import copy
import re
import tempfile

import pandas as pd
from django.test import override_settings
from django.urls import get_resolver, reverse
from rest_framework.test import APITestCase

from alerts import pipeline_loader
from alerts.models import Alert, Flow
from ml import risk
from ml.features import build_features
from ml.synthetic_world import build_world, flow_for_level, typical_flow
import numpy as np


def route_strings(patterns, prefix=""):
    for p in patterns:
        if hasattr(p, "url_patterns"):
            yield from route_strings(p.url_patterns, prefix + str(p.pattern))
        else:
            yield prefix + str(p.pattern)


class ApiTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.world = build_world()
        cls.low = flow_for_level(cls.world, "Low")
        cls.med = flow_for_level(cls.world, "Medium")
        cls.high = flow_for_level(cls.world, "High", port=22)

    def setUp(self):
        self.pipeline = copy.deepcopy(self.world)           # each test gets an unmodified baseline
        pipeline_loader.set_pipeline(self.pipeline)

    def tearDown(self):
        pipeline_loader.set_pipeline(None)

    def post(self, flows, **extra):
        return self.client.post(reverse("score"), {"flows": flows, **extra}, format="json")

    # ---- scoring -----------------------------------------------------------------
    def test_normal_flow(self):
        r = self.post([self.low])
        self.assertEqual(r.status_code, 201)
        res = r.data["results"][0]
        self.assertEqual(res["risk_level"], "Low")
        self.assertIsNone(res["alert_id"])
        self.assertIsNone(res["explanation"])
        self.assertTrue(res["recommended_response"].startswith("Monitor"))
        self.assertEqual((Flow.objects.count(), Alert.objects.count()), (1, 0))
        self.assertEqual(r.data["counts"], {"Low": 1, "Medium": 0, "High": 0})

    def test_medium_alert(self):
        r = self.post([self.med])
        self.assertEqual(r.status_code, 201)
        res = r.data["results"][0]
        self.assertEqual(res["risk_level"], "Medium")
        alert = Alert.objects.get(id=res["alert_id"])
        self.assertEqual(alert.risk_level, "Medium")
        self.assertEqual(alert.recommended_action, "Investigate / review")
        self.assertIn("not proof of malicious activity", alert.explanation)

    def test_high_alert(self):
        r = self.post([self.high])
        res = r.data["results"][0]
        self.assertEqual(res["risk_level"], "High")
        alert = Alert.objects.get(id=res["alert_id"])
        self.assertEqual(alert.recommended_action, "Investigate immediately")
        self.assertIn("consider containment according to your organization's security policy",
                      alert.recommended_response)
        self.assertEqual(alert.automated_action, "none")
        self.assertIn("no blocking", alert.note.lower())
        self.assertEqual(alert.flow.risk_score, res["risk_score"])
        self.assertEqual(alert.context["service"], "port 22 (SSH)")
        self.assertTrue(alert.anomaly["evidence"] >= 0 and alert.baseline_deviation["evidence"] > 0)

    # ---- persisted explanation ----------------------------------------------------
    def test_explanation_is_persisted_not_recalculated(self):
        first = self.post([self.high]).data["results"][0]
        alert_id = first["alert_id"]
        stored = Alert.objects.get(id=alert_id)
        text, evidence = stored.explanation, copy.deepcopy(stored.baseline_deviation)
        self.assertEqual(text, first["explanation"])

        # the adaptive baseline moves later ...
        for b in self.pipeline.baseline.baselines.values():
            b.median = b.median + 1.0
        second = self.post([self.high]).data["results"][0]
        self.assertNotEqual(second["deviation_score"], first["deviation_score"])   # scoring does use the new baseline

        # ... but the historical alert still shows what was generated at detection time
        detail = self.client.get(reverse("alert-detail", args=[alert_id])).data
        self.assertEqual(detail["explanation"], text)
        self.assertEqual(detail["baseline_deviation"], evidence)
        self.assertEqual(detail["flow"]["deviation_score"], first["deviation_score"])
        self.assertEqual(Alert.objects.get(id=alert_id).explanation, text)

        # alerts cannot be edited after creation
        stored.explanation = "changed"
        with self.assertRaises(ValueError):
            stored.save()

    # ---- retrieval ---------------------------------------------------------------
    def _seed(self):
        self.post([self.low]); self.post([self.med]); self.post([self.high])

    def test_alert_list_and_filters(self):
        self._seed()
        r = self.client.get(reverse("alert-list"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["count"], 2)
        self.assertEqual([a["risk_level"] for a in r.data["results"]], ["High", "Medium"])   # newest first
        self.assertEqual(self.client.get(reverse("alert-list"), {"level": "high"}).data["count"], 1)
        self.assertEqual(self.client.get(reverse("alert-list"), {"port": 22}).data["count"], 1)
        self.assertEqual(self.client.get(reverse("alert-list"), {"min_risk": 60}).data["count"], 1)
        by_risk = self.client.get(reverse("alert-list"), {"ordering": "risk"}).data["results"]
        self.assertEqual(by_risk[0]["risk_level"], "High")
        paged = self.client.get(reverse("alert-list"), {"page_size": 1}).data
        self.assertEqual(len(paged["results"]), 1)
        self.assertIsNotNone(paged["next"])
        for bad in ({"level": "Low"}, {"level": "bogus"}, {"port": "x"}, {"min_risk": "x"}, {"ordering": "x"}):
            self.assertEqual(self.client.get(reverse("alert-list"), bad).status_code, 400, bad)

    def test_alert_detail(self):
        self._seed()
        alert = Alert.objects.get(risk_level="High")
        r = self.client.get(reverse("alert-detail", args=[alert.id]))
        self.assertEqual(r.status_code, 200)
        for key in ("risk_score", "risk_level", "anomaly", "baseline_deviation", "context", "drivers",
                    "explanation", "recommended_action", "recommended_response", "automated_action", "flow"):
            self.assertIn(key, r.data)
        self.assertEqual(len(r.data["flow"]["features"]), 21)
        self.assertEqual(self.client.get(reverse("alert-detail", args=[999999])).status_code, 404)

    def test_alert_endpoints_are_read_only(self):
        self._seed()
        aid = Alert.objects.first().id
        for url in (reverse("alert-list"), reverse("alert-detail", args=[aid])):
            for method in ("post", "put", "patch", "delete"):
                self.assertEqual(getattr(self.client, method)(url, {}, format="json").status_code, 405, (url, method))
        self.assertEqual(self.client.get(reverse("score")).status_code, 405)

    def test_summary(self):
        empty = self.client.get(reverse("summary")).data
        self.assertEqual((empty["total_flows"], empty["total_alerts"]), (0, 0))
        self.assertEqual(empty["alerts_by_risk_level"], {"Low": 0, "Medium": 0, "High": 0})
        self._seed()
        s = self.client.get(reverse("summary")).data
        self.assertEqual((s["total_flows"], s["total_alerts"]), (3, 2))
        self.assertEqual(s["flows_by_risk_level"], {"Low": 1, "Medium": 1, "High": 1})
        self.assertEqual(s["alerts_by_risk_level"], {"Low": 0, "Medium": 1, "High": 1})
        self.assertEqual(sum(s["alerts_by_driver"].values()), 2)
        self.assertTrue(any(p["port"] == 22 for p in s["top_alert_ports"]))
        self.assertTrue(30 <= s["average_alert_risk"] <= 100)
        self.assertIn("not confirmation of an attack", s["disclaimer"])

    # ---- validation and errors ---------------------------------------------------
    def test_invalid_input(self):
        ok = typical_flow(np.random.default_rng(0))
        bad_payloads = {
            "missing flows": {},
            "empty list": {"flows": []},
            "flows not a list": {"flows": "x"},
            "flow not an object": {"flows": [1]},
            "missing field": {"flows": [{k: v for k, v in ok.items() if k != "Flow IAT Max"}]},
            "string value": {"flows": [{**ok, "Flow Duration": "abc"}]},
            "null value": {"flows": [{**ok, "Flow Duration": None}]},
            "port out of range": {"flows": [{**ok, "Destination Port": 70000}]},
            "bad learn flag": {"flows": [ok], "learn": "maybe"},
            "too many flows": {"flows": [ok] * 1001},
        }
        for name, payload in bad_payloads.items():
            r = self.client.post(reverse("score"), payload, format="json")
            self.assertEqual(r.status_code, 400, name)
            self.assertIn("error", r.data, name)
        r = self.client.post(reverse("score"), [ok], format="json")           # body is a list, not an object
        self.assertEqual(r.status_code, 400)
        self.assertEqual((Flow.objects.count(), Alert.objects.count()), (0, 0))   # nothing persisted

    def test_models_unavailable(self):
        pipeline_loader.set_pipeline(None)
        with tempfile.TemporaryDirectory() as empty, override_settings(ML_ARTIFACTS_DIR=empty):
            ok = typical_flow(np.random.default_rng(0))
            self.assertEqual(self.post([ok]).status_code, 503)
            self.assertEqual(self.post([{"Destination Port": 80}]).status_code, 400)   # validated before models load
        self.assertEqual(Flow.objects.count(), 0)

    # ---- Step 5 unchanged ---------------------------------------------------------
    def test_step5_risk_unchanged(self):
        res = self.post([self.high]).data["results"][0]
        X, ctx = build_features(pd.DataFrame([self.high]))
        w = self.world
        direct = w.scorer.score(w.detector.score(X), w.baseline.deviation_score(w.baseline.robust_z(X, ctx)),
                                ctx["Destination Port"]).iloc[0]
        self.assertAlmostEqual(direct["risk_score"], res["risk_score"], delta=0.06)
        self.assertEqual(direct["risk_level"], res["risk_level"])
        self.assertEqual(Flow.objects.get(id=res["flow_id"]).risk_score, res["risk_score"])
        # constants of the Step 5 formula are locked
        self.assertEqual((risk.W_ANOMALY, risk.W_DEVIATION), (0.5, 0.5))
        self.assertEqual((risk.ANOMALY_P_LOW, risk.ANOMALY_P_HIGH, risk.DEVIATION_LOW, risk.DEVIATION_HIGH),
                         (0.90, 0.999, 3.0, 10.0))
        self.assertEqual((risk.LOW_MAX, risk.HIGH_MIN), (30.0, 60.0))
        self.assertEqual((risk.CTX_SENSITIVE, risk.CTX_UNCOMMON, risk.CTX_COMMON), (1.3, 1.15, 1.0))

    # ---- no destructive actions ----------------------------------------------------
    def test_no_destructive_endpoints(self):
        routes = list(route_strings(get_resolver().url_patterns))
        self.assertTrue(routes)
        for route in routes:
            self.assertIsNone(re.search(r"block|isolat|quarantin|disable|terminat|contain|kill|ban|lock", route, re.I), route)
