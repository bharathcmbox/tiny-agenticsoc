"""Tests for `socagent ledger` totals (per model, per provider, overall). Run: cd agent && uv run pytest

M.LEDGER is always patched to a temporary file, so the real results/ directory is never touched.
No network, Wazuh indexer, LLM or DFIR-IRIS is involved.
"""
import argparse
import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import socagent.__main__ as M

A_PRE = "anthropic:claude-haiku-5-5"
OR_PRE = "openrouter:anthropic/claude-haiku-5.5"
A_BARE = "claude-haiku-5-5"            # no prefix, claude-* => anthropic
OR_BARE = "google/gemini-3-flash"      # no prefix, slash => openrouter


def row(model, cost, escalate=False, verdict="benign", latency=1.0, **extra):
    r = {"model": model, "cost_usd": cost, "escalate": escalate, "verdict": verdict, "latency_s": latency,
         "bundle_key": f"h|1|{model}|{cost}"}
    r.update(extra)
    return r


ROWS = [
    row(A_PRE, 0.0012, escalate=True, verdict="malicious", latency=2.0),
    row(A_PRE, 0.0021, escalate=False, verdict="benign", latency=4.0),
    row(A_BARE, 0.0005, escalate=True, verdict="suspicious", latency=3.0),
    row(OR_PRE, 0.0011, escalate=False, latency=1.0),
    row(OR_PRE, 0.0022, escalate=True, verdict="malicious", latency=2.0),
    row(OR_PRE, 0.0030, escalate=True, verdict="malicious", latency=3.0),
    row(OR_BARE, 0.0003, escalate=False, latency=5.0),
]
# expected totals
A_COST = 0.0012 + 0.0021 + 0.0005            # 0.0038
OR_COST = 0.0011 + 0.0022 + 0.0030 + 0.0003  # 0.0066
TOTAL_COST = A_COST + OR_COST                # 0.0104


class LedgerTotalsPerModel(unittest.TestCase):
    def setUp(self):
        self.t = M.ledger_totals([dict(r) for r in ROWS])

    def test_models_keyed_by_model_string(self):
        self.assertEqual(set(self.t["models"]), {A_PRE, OR_PRE, A_BARE, OR_BARE})

    def test_bundles_per_model(self):
        m = self.t["models"]
        self.assertEqual({k: v["bundles"] for k, v in m.items()}, {A_PRE: 2, A_BARE: 1, OR_PRE: 3, OR_BARE: 1})

    def test_cost_per_model(self):
        m = self.t["models"]
        self.assertAlmostEqual(m[A_PRE]["cost_usd"], 0.0033)
        self.assertAlmostEqual(m[A_BARE]["cost_usd"], 0.0005)
        self.assertAlmostEqual(m[OR_PRE]["cost_usd"], 0.0063)
        self.assertAlmostEqual(m[OR_BARE]["cost_usd"], 0.0003)

    def test_escalated_per_model(self):
        m = self.t["models"]
        self.assertEqual({k: v["escalated"] for k, v in m.items()}, {A_PRE: 1, A_BARE: 1, OR_PRE: 2, OR_BARE: 0})

    def test_provider_of_each_model(self):
        m = self.t["models"]
        self.assertEqual(m[A_PRE]["provider"], "anthropic")
        self.assertEqual(m[A_BARE]["provider"], "anthropic", "unprefixed claude-* counts as anthropic")
        self.assertEqual(m[OR_PRE]["provider"], "openrouter")
        self.assertEqual(m[OR_BARE]["provider"], "openrouter", "unprefixed vendor/model counts as openrouter")

    def test_verdict_counts(self):
        m = self.t["models"]
        self.assertEqual(m[A_PRE]["verdicts"], {"malicious": 1, "benign": 1})
        self.assertEqual(m[OR_PRE]["verdicts"], {"benign": 1, "malicious": 2})

    def test_average_latency(self):
        m = self.t["models"]
        self.assertAlmostEqual(m[A_PRE]["avg_latency_s"], 3.0)
        self.assertAlmostEqual(m[OR_PRE]["avg_latency_s"], 2.0)
        self.assertAlmostEqual(m[OR_BARE]["avg_latency_s"], 5.0)


class LedgerTotalsPerProvider(unittest.TestCase):
    def setUp(self):
        self.t = M.ledger_totals([dict(r) for r in ROWS])

    def test_exactly_two_providers(self):
        self.assertEqual(set(self.t["providers"]), {"anthropic", "openrouter"})

    def test_provider_bundles(self):
        p = self.t["providers"]
        self.assertEqual(p["anthropic"]["bundles"], 3)
        self.assertEqual(p["openrouter"]["bundles"], 4)

    def test_provider_cost(self):
        p = self.t["providers"]
        self.assertAlmostEqual(p["anthropic"]["cost_usd"], A_COST)
        self.assertAlmostEqual(p["openrouter"]["cost_usd"], OR_COST)

    def test_provider_distinct_model_count(self):
        p = self.t["providers"]
        self.assertEqual(p["anthropic"]["models"], 2)    # A_PRE, A_BARE (distinct ledger model strings)
        self.assertEqual(p["openrouter"]["models"], 2)   # OR_PRE, OR_BARE

    def test_model_count_is_distinct_not_rows(self):
        t = M.ledger_totals([row(OR_PRE, 0.001) for _ in range(5)])
        self.assertEqual(t["providers"]["openrouter"]["models"], 1)
        self.assertEqual(t["providers"]["openrouter"]["bundles"], 5)
        self.assertNotIn("anthropic", t["providers"])

    def test_providers_sum_to_total(self):
        p = self.t["providers"]
        self.assertEqual(sum(v["bundles"] for v in p.values()), self.t["total"]["bundles"])
        self.assertAlmostEqual(sum(v["cost_usd"] for v in p.values()), self.t["total"]["cost_usd"])


class LedgerTotalsOverall(unittest.TestCase):
    def test_total(self):
        t = M.ledger_totals([dict(r) for r in ROWS])
        self.assertEqual(t["total"]["bundles"], 7)
        self.assertAlmostEqual(t["total"]["cost_usd"], TOTAL_COST)

    def test_empty_rows(self):
        t = M.ledger_totals([])
        self.assertEqual(t["models"], {})
        self.assertEqual(t["providers"], {})
        self.assertEqual(t["total"]["bundles"], 0)
        self.assertAlmostEqual(t["total"]["cost_usd"], 0.0)

    def test_does_not_mutate_rows(self):
        rows = [dict(r) for r in ROWS]
        before = json.dumps(rows, sort_keys=True)
        M.ledger_totals(rows)
        self.assertEqual(json.dumps(rows, sort_keys=True), before)


class LedgerTotalsMissingFields(unittest.TestCase):
    def test_missing_latency(self):
        r = row(A_PRE, 0.001); del r["latency_s"]
        t = M.ledger_totals([r, row(A_PRE, 0.002, latency=4.0)])
        self.assertEqual(t["models"][A_PRE]["bundles"], 2)
        self.assertAlmostEqual(t["models"][A_PRE]["avg_latency_s"], 2.0)   # missing counts as 0
        self.assertAlmostEqual(t["total"]["cost_usd"], 0.003)

    def test_missing_escalate(self):
        r = row(OR_PRE, 0.001); del r["escalate"]
        t = M.ledger_totals([r])
        self.assertEqual(t["models"][OR_PRE]["escalated"], 0)
        self.assertEqual(t["providers"]["openrouter"]["bundles"], 1)

    def test_missing_both(self):
        r = row(A_BARE, 0.004); del r["escalate"]; del r["latency_s"]
        t = M.ledger_totals([r])
        self.assertEqual(t["models"][A_BARE]["escalated"], 0)
        self.assertAlmostEqual(t["models"][A_BARE]["avg_latency_s"], 0.0)
        self.assertAlmostEqual(t["total"]["cost_usd"], 0.004)

    def test_null_latency(self):
        t = M.ledger_totals([row(A_PRE, 0.001, latency=None)])
        self.assertAlmostEqual(t["models"][A_PRE]["avg_latency_s"], 0.0)


class CmdLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "triage.jsonl"

    def run_ledger(self, rows=None, text=None):
        if text is None:
            text = "".join(json.dumps(r) + "\n" for r in rows)
        self.path.write_text(text)
        buf = io.StringIO()
        with mock.patch.object(M, "LEDGER", self.path), contextlib.redirect_stdout(buf):
            M.cmd_ledger(argparse.Namespace(), None)
        return [ln for ln in buf.getvalue().splitlines() if ln.strip()]

    @staticmethod
    def money(line):
        m = re.findall(r"\$(\d+\.\d{4})\b total", line)
        assert len(m) == 1, line
        return m[0]

    def test_provider_lines(self):
        lines = self.run_ledger(ROWS)
        for name, cost, bundles, models in (("anthropic", "0.0038", 3, 2), ("openrouter", "0.0066", 4, 2)):
            with self.subTest(provider=name):
                hits = [ln for ln in lines if ln.split()[:2] == ["provider", name]]
                self.assertEqual(len(hits), 1, lines)
                self.assertEqual(self.money(hits[0]), cost)
                self.assertRegex(hits[0], rf"\b{bundles} bundles\b")
                self.assertRegex(hits[0], rf"\b{models} model\(s\)")
        self.assertEqual(len([ln for ln in lines if ln.startswith("provider ")]), 2)

    def test_total_line(self):
        lines = self.run_ledger(ROWS)
        hits = [ln for ln in lines if ln.split()[0] == "total"]
        self.assertEqual(len(hits), 1, lines)
        self.assertEqual(self.money(hits[0]), "0.0104")
        self.assertRegex(hits[0], r"\b7 bundles\b")

    def test_one_line_per_model(self):
        lines = self.run_ledger(ROWS)
        for model, cost, n in ((A_PRE, "0.0033", 2), (A_BARE, "0.0005", 1), (OR_PRE, "0.0063", 3),
                               (OR_BARE, "0.0003", 1)):
            with self.subTest(model=model):
                hits = [ln for ln in lines if ln.split()[0] == model]
                self.assertEqual(len(hits), 1, lines)
                self.assertEqual(self.money(hits[0]), cost)
                self.assertRegex(hits[0], rf"\b{n} triaged\b")
        # 4 model lines + 2 provider lines + 1 total line, nothing else
        self.assertEqual(len(lines), 7, lines)

    def test_single_provider(self):
        lines = self.run_ledger([row(OR_BARE, 0.00015), row(OR_BARE, 0.00025)])
        prov = [ln for ln in lines if ln.startswith("provider ")]
        self.assertEqual(len(prov), 1)
        self.assertEqual(prov[0].split()[1], "openrouter")
        self.assertEqual(self.money(prov[0]), "0.0004")

    def test_blank_lines_and_missing_fields_tolerated(self):
        r1 = row(A_PRE, 0.001); del r1["latency_s"]
        r2 = row(A_PRE, 0.002); del r2["escalate"]
        lines = self.run_ledger(text=json.dumps(r1) + "\n\n" + json.dumps(r2) + "\n  \n")
        total = [ln for ln in lines if ln.split()[0] == "total"]
        self.assertEqual(self.money(total[0]), "0.0030")

    def test_missing_ledger_exits(self):
        missing = Path(self.tmp.name) / "nope.jsonl"
        buf = io.StringIO()
        with mock.patch.object(M, "LEDGER", missing), contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                M.cmd_ledger(argparse.Namespace(), None)
        self.assertNotIn(cm.exception.code, (0, None))
        self.assertFalse(missing.exists(), "cmd_ledger must not create the ledger")
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
