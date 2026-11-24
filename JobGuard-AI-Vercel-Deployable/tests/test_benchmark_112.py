"""Formal 112-Sample Precision/Recall/FPR Regression Benchmark & Security/Efficiency Tests."""
from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.evidence_engine import build_verification_report
from backend.main import app
from backend.schemas import VerifyRequest
from backend.url_inspector import inspect_url_structurally


class TestJobGuardBenchmarkAndHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)
        bench_path = Path(__file__).resolve().parent / "benchmark_112.json"
        cls.samples = json.loads(bench_path.read_text(encoding="utf-8"))

    def test_01_full_112_sample_benchmark_recall_and_zero_fpr(self) -> None:
        """Verify 100% recall on SCAM-001..100 and 0% false positives on LEGIT-001..012."""
        tp = fn = tn = fp = 0

        async def _eval() -> None:
            nonlocal tp, fn, tn, fp
            for s in self.samples:
                rep = await build_verification_report(VerifyRequest(text=s["text"]))
                pred_scam = rep.risk_level.value in ("HIGH RISK", "MEDIUM RISK")
                if s["label"] == "SCAM":
                    if pred_scam:
                        tp += 1
                    else:
                        fn += 1
                else:
                    if not pred_scam:
                        tn += 1
                    else:
                        fp += 1

        asyncio.run(_eval())
        self.assertEqual(tp, 100, f"Expected 100/100 scam recall, missed {fn}")
        self.assertEqual(fp, 0, f"Expected 0/12 false positives, got {fp}")
        self.assertEqual(tn, 12)

    def test_02_security_headers_and_non_wildcard_cors(self) -> None:
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(resp.headers.get("x-frame-options"), "SAMEORIGIN")
        self.assertIn("camera=()", resp.headers.get("permissions-policy", ""))

    def test_03_url_inspector_lru_cache_efficiency(self) -> None:
        inspect_url_structurally.cache_clear()
        u = "https://infosys.careers-verification.xyz/apply"
        r1 = inspect_url_structurally(u)
        r2 = inspect_url_structurally(u)
        self.assertIs(r1, r2)
        info = inspect_url_structurally.cache_info()
        self.assertGreaterEqual(info.hits, 1)


if __name__ == "__main__":
    unittest.main()
