"""Tests for `socagent investigate` queue selection (--min-severity). Run: cd agent && uv run pytest

incidents.load/save, Indexer, LLM, SocTools, investigate.investigate/save and cmd_cases are always
patched, so no results files, network, Wazuh indexer, LLM or DFIR-IRIS are touched.
"""
import argparse
import contextlib
import io
import sys
import types
import unittest
from unittest import mock

import socagent.__main__ as M
from socagent import incidents as I
from socagent import investigate as INV

D = "2026-11-01T"
SETTINGS = types.SimpleNamespace(investigate_model="anthropic:claude-sonnet-5-5")


def inc(id, severity, first, status="new"):
    return I.Incident(id=id, status=status, severity=severity, title=f"title of {id}", hosts=["win-victim"],
                      first=first, last=first, verdicts={"malicious": 1}, techniques=[], max_level=10,
                      bundle_keys=[f"win-victim|1|{first}"])


class Run:
    """Result of one cmd_investigate run: investigated ids in call order, stdout, and the mocks."""


def run_investigate(incidents, *, ids=(), min_severity="low", effort="medium"):
    r = Run()
    r.called = []                    # incident ids passed to investigate(), in call order
    r.status_at_call = {}            # incident status at the moment investigate() was called
    r.saves = []                     # snapshot of {id: status} at each incidents.save()

    def fake_investigate(llm, model, tools, incident, effort="medium", log=print):
        r.called.append(incident.id)
        r.status_at_call[incident.id] = incident.status
        r.model, r.effort = model, effort
        return INV.Investigation(incident_id=incident.id, model="m", started="t", status="complete",
                                 report={"verdict": "benign", "confidence": 0.9, "title": "x"})

    def fake_save(incs):
        r.saves.append({i.id: i.status for i in incs})

    indexer = mock.MagicMock(name="Indexer")
    indexer.return_value.__enter__.return_value = mock.MagicMock(name="ix")
    indexer.return_value.__exit__.return_value = False
    buf = io.StringIO()
    with mock.patch("socagent.incidents.load", return_value=list(incidents)) as load, \
            mock.patch("socagent.incidents.save", side_effect=fake_save), \
            mock.patch.object(M, "Indexer", indexer), \
            mock.patch("socagent.investigate.investigate", side_effect=fake_investigate) as inv, \
            mock.patch("socagent.investigate.save", return_value=("j", "md")) as inv_save, \
            mock.patch("socagent.llm.LLM") as llm, \
            mock.patch("socagent.tools.SocTools") as tools, \
            mock.patch.object(M, "cmd_cases") as cases, \
            contextlib.redirect_stdout(buf):
        r.ret = M.cmd_investigate(argparse.Namespace(id=list(ids), effort=effort, no_iris=True,
                                                     min_severity=min_severity), SETTINGS)
    assert load.called, "cmd_investigate must read incidents via incidents.load()"
    r.out, r.inv, r.inv_save, r.llm, r.tools, r.indexer, r.cases = (
        buf.getvalue(), inv, inv_save, llm, tools, indexer, cases)
    return r


class InvestigateOrdering(unittest.TestCase):
    def test_severity_order_critical_high_medium_low(self):
        low = inc("INC-20261101-001", "low", D + "08:00:00+0000")
        med = inc("INC-20261101-002", "medium", D + "08:10:00+0000")
        high = inc("INC-20261101-003", "high", D + "08:20:00+0000")
        crit = inc("INC-20261101-004", "critical", D + "08:30:00+0000")   # newest, but most severe
        r = run_investigate([low, med, high, crit], min_severity="low")
        self.assertEqual(r.called, [crit.id, high.id, med.id, low.id])

    def test_oldest_first_within_severity(self):
        newer = inc("INC-20261101-001", "high", D + "12:00:00+0000")
        older = inc("INC-20261101-002", "high", D + "08:00:00+0000")
        middle = inc("INC-20261101-003", "high", D + "10:00:00+0000")
        r = run_investigate([newer, older, middle], min_severity="low")
        self.assertEqual(r.called, [older.id, middle.id, newer.id])

    def test_oldest_first_across_days(self):
        later = inc("INC-20261102-001", "medium", "2026-11-02T01:00:00+0000")
        earlier = inc("INC-20261031-001", "medium", "2026-10-31T23:00:00+0000")
        r = run_investigate([later, earlier], min_severity="low")
        self.assertEqual(r.called, [earlier.id, later.id])

    def test_full_mixed_ordering(self):
        h_new = inc("INC-20261101-001", "high", D + "10:30:00+0000")
        c_new = inc("INC-20261101-002", "critical", D + "10:20:00+0000")
        l_old = inc("INC-20261101-003", "low", D + "07:00:00+0000")
        h_old = inc("INC-20261101-004", "high", D + "10:00:00+0000")
        m_new = inc("INC-20261101-005", "medium", D + "11:00:00+0000")
        c_old = inc("INC-20261101-006", "critical", D + "10:10:00+0000")
        m_old = inc("INC-20261101-007", "medium", D + "09:00:00+0000")
        r = run_investigate([h_new, c_new, l_old, h_old, m_new, c_old, m_old], min_severity="low")
        self.assertEqual(r.called, [c_old.id, c_new.id, h_old.id, h_new.id, m_old.id, m_new.id, l_old.id])

    def test_passes_model_and_effort(self):
        r = run_investigate([inc("INC-20261101-001", "high", D + "10:00:00+0000")], effort="high")
        self.assertEqual(r.model, SETTINGS.investigate_model)
        self.assertEqual(r.effort, "high")


class InvestigateFloor(unittest.TestCase):
    def setUp(self):
        self.crit = inc("INC-20261101-001", "critical", D + "10:00:00+0000")
        self.high = inc("INC-20261101-002", "high", D + "09:00:00+0000")
        self.med = inc("INC-20261101-003", "medium", D + "08:00:00+0000")
        self.low = inc("INC-20261101-004", "low", D + "07:00:00+0000")
        self.all = [self.low, self.med, self.high, self.crit]

    def test_high_floor_skips_medium_and_low(self):
        self.assertEqual(run_investigate(self.all, min_severity="high").called, [self.crit.id, self.high.id])

    def test_critical_floor_runs_only_critical(self):
        self.assertEqual(run_investigate(self.all, min_severity="critical").called, [self.crit.id])

    def test_medium_floor_skips_low(self):
        self.assertEqual(run_investigate(self.all, min_severity="medium").called,
                         [self.crit.id, self.high.id, self.med.id])

    def test_low_floor_runs_everything(self):
        self.assertEqual(run_investigate(self.all, min_severity="low").called,
                         [self.crit.id, self.high.id, self.med.id, self.low.id])

    def test_skipped_incidents_keep_status(self):
        r = run_investigate(self.all, min_severity="high")
        self.assertEqual(self.med.status, "new")
        self.assertEqual(self.low.status, "new")
        self.assertIsNone(self.med.investigation)
        self.assertIsNone(self.low.investigation)
        self.assertTrue(r.saves)


class InvestigateStatusFilter(unittest.TestCase):
    def test_non_new_never_investigated(self):
        new = inc("INC-20261101-010", "low", D + "11:00:00+0000")
        others = [inc("INC-20261101-011", "critical", D + "09:00:00+0000", status="investigated"),
                  inc("INC-20261101-012", "critical", D + "09:01:00+0000", status="investigating"),
                  inc("INC-20261101-013", "critical", D + "09:02:00+0000", status="closed"),
                  inc("INC-20261101-014", "high", D + "09:03:00+0000", status="needs_human")]
        before = {i.id: i.status for i in others}
        r = run_investigate([*others, new], min_severity="low")
        self.assertEqual(r.called, [new.id])
        self.assertEqual({i.id: i.status for i in others}, before)

    def test_only_non_new_is_empty(self):
        r = run_investigate([inc("INC-20261101-001", "critical", D + "10:00:00+0000", status="investigated")],
                            min_severity="low")
        self.assertEqual(r.called, [])
        self.assertTrue(r.out.strip())


class InvestigateStatusUpdates(unittest.TestCase):
    def test_incidents_end_up_investigated(self):
        a = inc("INC-20261101-001", "critical", D + "10:00:00+0000")
        b = inc("INC-20261101-002", "medium", D + "09:00:00+0000")
        r = run_investigate([a, b], min_severity="low")
        self.assertEqual(r.called, [a.id, b.id])
        self.assertEqual(a.status, "investigated")
        self.assertEqual(b.status, "investigated")
        self.assertEqual(a.investigation["verdict"], "benign")
        self.assertEqual(a.investigation["confidence"], 0.9)
        self.assertEqual(a.investigation["report"], "md")

    def test_marked_investigating_while_running_and_persisted(self):
        a = inc("INC-20261101-001", "high", D + "10:00:00+0000")
        r = run_investigate([a], min_severity="low")
        self.assertEqual(r.status_at_call[a.id], "investigating")
        self.assertIn({a.id: "investigating"}, r.saves, "the 'investigating' state must be saved before the run")
        self.assertEqual(r.saves[-1], {a.id: "investigated"}, "final state must be persisted")
        r.inv_save.assert_called_once()

    def test_save_persists_full_incident_list(self):
        """The queue must hold the same objects as the loaded list, so saving the list records the update."""
        a = inc("INC-20261101-001", "high", D + "10:00:00+0000")
        skip = inc("INC-20261101-002", "low", D + "09:00:00+0000")
        done = inc("INC-20261101-003", "critical", D + "08:00:00+0000", status="closed")
        r = run_investigate([a, skip, done], min_severity="high")
        self.assertEqual(r.saves[-1], {a.id: "investigated", skip.id: "new", done.id: "closed"})


class InvestigateExplicitIds(unittest.TestCase):
    def test_ids_bypass_floor_and_status(self):
        low_closed = inc("INC-20261101-001", "low", D + "10:00:00+0000", status="investigated")
        med_new = inc("INC-20261101-002", "medium", D + "09:00:00+0000")
        crit_new = inc("INC-20261101-003", "critical", D + "08:00:00+0000")
        r = run_investigate([low_closed, med_new, crit_new], ids=[low_closed.id, med_new.id],
                            min_severity="critical")
        self.assertEqual(sorted(r.called), sorted([low_closed.id, med_new.id]))
        self.assertNotIn(crit_new.id, r.called)
        self.assertEqual(low_closed.status, "investigated")
        self.assertEqual(crit_new.status, "new")

    def test_single_id_below_default_queue_floor(self):
        low = inc("INC-20261101-001", "low", D + "10:00:00+0000", status="closed")
        r = run_investigate([low], ids=[low.id], min_severity="high")
        self.assertEqual(r.called, [low.id])

    def test_unknown_id_exits(self):
        a = inc("INC-20261101-001", "high", D + "10:00:00+0000")
        with self.assertRaises(SystemExit) as cm:
            run_investigate([a], ids=["INC-20990101-999"])
        self.assertNotIn(cm.exception.code, (0, None))


class InvestigateEmptyQueue(unittest.TestCase):
    def assert_empty(self, incidents, min_severity):
        r = run_investigate(incidents, min_severity=min_severity)
        self.assertIsNone(r.ret)
        self.assertTrue(r.out.strip(), "empty queue must print a message")
        self.assertNotIn("INC-", r.out)
        r.inv.assert_not_called()
        r.inv_save.assert_not_called()
        r.llm.assert_not_called()
        r.indexer.assert_not_called()
        r.tools.assert_not_called()
        r.cases.assert_not_called()
        self.assertEqual(r.saves, [])

    def test_no_incidents(self):
        self.assert_empty([], "low")

    def test_only_below_floor(self):
        self.assert_empty([inc("INC-20261101-001", "medium", D + "10:00:00+0000"),
                           inc("INC-20261101-002", "high", D + "10:01:00+0000")], "critical")

    def test_only_non_new(self):
        self.assert_empty([inc("INC-20261101-001", "critical", D + "10:00:00+0000", status="closed")], "low")


class InvestigateNoIris(unittest.TestCase):
    def test_no_iris_never_pushes(self):
        r = run_investigate([inc("INC-20261101-001", "high", D + "10:00:00+0000")])
        r.cases.assert_not_called()


class InvestigateArgparse(unittest.TestCase):
    """Drive main() with Settings.load and the command patched, so no real environment is needed."""

    def parse(self, cmd, *argv):
        target = {"investigate": "cmd_investigate", "queue": "cmd_queue"}[cmd]
        with mock.patch.object(sys, "argv", ["socagent", cmd, *argv]), \
                mock.patch.object(M.Settings, "load", return_value=None), \
                mock.patch.object(M, target) as fn, \
                mock.patch("socagent.incidents.load", return_value=[]):
            M.main()
        fn.assert_called_once()
        return fn.call_args.args[0]

    def test_investigate_default_min_severity_is_low(self):
        a = self.parse("investigate")
        self.assertEqual(a.min_severity, "low")
        self.assertEqual(a.id, [])
        self.assertFalse(a.no_iris)

    def test_queue_default_stays_high(self):
        self.assertEqual(self.parse("queue").min_severity, "high")

    def test_default_investigates_every_new_incident(self):
        """Default floor 'low' keeps today's behaviour: every new incident, whatever its severity."""
        default = self.parse("investigate").min_severity
        incs = [inc("INC-20261101-001", "low", D + "10:00:00+0000"),
                inc("INC-20261101-002", "medium", D + "10:01:00+0000"),
                inc("INC-20261101-003", "high", D + "10:02:00+0000"),
                inc("INC-20261101-004", "critical", D + "10:03:00+0000"),
                inc("INC-20261101-005", "critical", D + "10:04:00+0000", status="closed")]
        r = run_investigate(incs, min_severity=default)
        self.assertEqual(sorted(r.called), [i.id for i in incs[:4]])

    def test_valid_choices_accepted(self):
        for v in ("low", "medium", "high", "critical"):
            self.assertEqual(self.parse("investigate", "--min-severity", v).min_severity, v)

    def test_ids_and_flag_together(self):
        a = self.parse("investigate", "INC-20261101-001", "--min-severity", "critical")
        self.assertEqual(a.id, ["INC-20261101-001"])
        self.assertEqual(a.min_severity, "critical")

    def test_invalid_value_rejected(self):
        for bad in ("severe", "HIGH", "", "4", "info"):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    self.parse("investigate", "--min-severity", bad)
                self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
