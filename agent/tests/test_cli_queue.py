"""Tests for the `socagent queue` CLI command. Run: cd agent && uv run pytest

incidents.load is always patched, so no results files, network, Wazuh/Indexer or LLM are touched.
"""
import argparse
import contextlib
import io
import sys
import unittest
from unittest import mock

import socagent.__main__ as M
from socagent import incidents as I

D = "2026-11-01T"


def inc(id, severity, first, status="new"):
    return I.Incident(id=id, status=status, severity=severity, title=f"title of {id}", hosts=["win-victim"],
                      first=first, last=first, verdicts={"malicious": 1}, techniques=[], max_level=10,
                      bundle_keys=[f"win-victim|1|{first}"])


def run_queue(incidents, **kw):
    """Run cmd_queue with incidents.load patched; return the printed lines (non-blank)."""
    buf = io.StringIO()
    with mock.patch("socagent.incidents.load", return_value=list(incidents)) as load, \
            contextlib.redirect_stdout(buf):
        ret = M.cmd_queue(argparse.Namespace(**kw), None)
    assert load.called, "cmd_queue must read incidents via incidents.load()"
    assert ret is None
    return [ln for ln in buf.getvalue().splitlines() if ln.strip()]


def ids_in(lines, incidents):
    """For each line, which of the incidents' ids it mentions (in line order)."""
    out = []
    for ln in lines:
        found = [i.id for i in incidents if i.id in ln]
        out.append(found)
    return out


class QueueOrdering(unittest.TestCase):
    def test_critical_before_high(self):
        high = inc("INC-20261101-001", "high", D + "09:00:00+0000")       # older, but less severe
        crit = inc("INC-20261101-002", "critical", D + "11:00:00+0000")
        lines = run_queue([high, crit], min_severity="high")
        self.assertEqual(ids_in(lines, [high, crit]), [[crit.id], [high.id]])

    def test_oldest_first_within_same_severity(self):
        newer = inc("INC-20261101-001", "high", D + "12:00:00+0000")
        older = inc("INC-20261101-002", "high", D + "08:00:00+0000")
        middle = inc("INC-20261101-003", "high", D + "10:00:00+0000")
        lines = run_queue([newer, older, middle], min_severity="high")
        self.assertEqual(ids_in(lines, [newer, older, middle]), [[older.id], [middle.id], [newer.id]])

    def test_oldest_first_across_days(self):
        later = inc("INC-20261102-001", "critical", "2026-11-02T01:00:00+0000")
        earlier = inc("INC-20261031-001", "critical", "2026-10-31T23:00:00+0000")
        lines = run_queue([later, earlier], min_severity="high")
        self.assertEqual(ids_in(lines, [later, earlier]), [[earlier.id], [later.id]])

    def test_full_ordering_mixed(self):
        h_new = inc("INC-20261101-001", "high", D + "10:30:00+0000")
        c_new = inc("INC-20261101-002", "critical", D + "10:20:00+0000")
        h_old = inc("INC-20261101-003", "high", D + "10:00:00+0000")
        c_old = inc("INC-20261101-004", "critical", D + "10:10:00+0000")
        m = inc("INC-20261101-005", "medium", D + "09:00:00+0000")
        allx = [h_new, c_new, h_old, c_old, m]
        lines = run_queue(allx, min_severity="medium")
        self.assertEqual(ids_in(lines, allx), [[c_old.id], [c_new.id], [h_old.id], [h_new.id], [m.id]])


class QueueLineContent(unittest.TestCase):
    def test_each_line_has_id_severity_and_first_seen(self):
        incs = [inc("INC-20261101-001", "critical", D + "10:00:00+0000"),
                inc("INC-20261101-002", "high", D + "11:15:30+0000"),
                inc("INC-20261101-003", "medium", D + "12:45:00+0000")]
        lines = run_queue(incs, min_severity="medium")
        self.assertEqual(len(lines), 3)
        by_id = {i.id: i for i in incs}
        for ln in lines:
            matches = [i for i in by_id if i in ln]
            self.assertEqual(len(matches), 1, ln)
            i = by_id[matches[0]]
            self.assertIn(i.severity, ln)
            self.assertIn(i.first, ln)

    def test_one_line_per_incident(self):
        incs = [inc(f"INC-20261101-00{n}", "high", D + f"1{n}:00:00+0000") for n in range(1, 5)]
        lines = run_queue(incs, min_severity="high")
        self.assertEqual(len(lines), 4)


class QueueFiltering(unittest.TestCase):
    def setUp(self):
        self.crit = inc("INC-20261101-001", "critical", D + "10:00:00+0000")
        self.high = inc("INC-20261101-002", "high", D + "10:05:00+0000")
        self.med = inc("INC-20261101-003", "medium", D + "10:10:00+0000")
        self.low = inc("INC-20261101-004", "low", D + "10:15:00+0000")
        self.all = [self.crit, self.high, self.med, self.low]

    def listed(self, **kw):
        lines = run_queue(self.all, **kw)
        return [x for found in ids_in(lines, self.all) for x in found]

    def test_high_floor_excludes_medium_and_low(self):
        self.assertEqual(self.listed(min_severity="high"), [self.crit.id, self.high.id])

    def test_medium_floor_includes_medium_not_low(self):
        self.assertEqual(self.listed(min_severity="medium"), [self.crit.id, self.high.id, self.med.id])

    def test_low_floor_includes_everything(self):
        self.assertEqual(self.listed(min_severity="low"),
                         [self.crit.id, self.high.id, self.med.id, self.low.id])

    def test_critical_floor_only_critical(self):
        self.assertEqual(self.listed(min_severity="critical"), [self.crit.id])

    def test_non_new_statuses_excluded(self):
        new = inc("INC-20261101-010", "high", D + "11:00:00+0000")
        others = [inc("INC-20261101-011", "critical", D + "09:00:00+0000", status="investigated"),
                  inc("INC-20261101-012", "critical", D + "09:01:00+0000", status="investigating"),
                  inc("INC-20261101-013", "critical", D + "09:02:00+0000", status="closed")]
        lines = run_queue([*others, new], min_severity="low")
        self.assertEqual(ids_in(lines, [*others, new]), [[new.id]])


class QueueEmpty(unittest.TestCase):
    def assert_empty_message(self, incidents, **kw):
        lines = run_queue(incidents, **kw)
        self.assertTrue(lines, "empty queue must print a message")
        text = "\n".join(lines)
        self.assertTrue(text.strip())
        for i in incidents:
            self.assertNotIn(i.id, text)
        self.assertNotIn("INC-", text)

    def test_no_incidents(self):
        self.assert_empty_message([], min_severity="high")

    def test_only_below_floor(self):
        self.assert_empty_message([inc("INC-20261101-001", "medium", D + "10:00:00+0000"),
                                   inc("INC-20261101-002", "low", D + "10:01:00+0000")], min_severity="high")

    def test_only_non_new(self):
        self.assert_empty_message([inc("INC-20261101-001", "critical", D + "10:00:00+0000", status="investigated"),
                                   inc("INC-20261101-002", "high", D + "10:01:00+0000", status="closed")],
                                  min_severity="high")


class QueueArgparse(unittest.TestCase):
    """Drive main() with Settings.load and cmd_queue patched, so no real environment is needed."""

    def parse(self, *argv):
        with mock.patch.object(sys, "argv", ["socagent", "queue", *argv]), \
                mock.patch.object(M.Settings, "load", return_value=None), \
                mock.patch.object(M, "cmd_queue") as cq, \
                mock.patch("socagent.incidents.load", return_value=[]):
            M.main()
        cq.assert_called_once()
        return cq.call_args.args[0]

    def test_default_min_severity_is_high(self):
        self.assertEqual(self.parse().min_severity, "high")

    def test_valid_choices_accepted(self):
        for v in ("low", "medium", "high", "critical"):
            self.assertEqual(self.parse("--min-severity", v).min_severity, v)

    def test_invalid_value_rejected(self):
        for bad in ("severe", "HIGH", "", "4"):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    self.parse("--min-severity", bad)
                self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
