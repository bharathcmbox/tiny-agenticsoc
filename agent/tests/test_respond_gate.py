"""Tests for the approval gate in socagent/respond.py. Run: cd agent && uv run pytest

Every test redirects R.DIR/R.ACTIONS/R.AUDIT to a temp dir, replaces R.Wazuh with a fake and patches
the `time` module used by socagent.respond (sleep + monotonic) with a fake clock, so nothing touches the
network, the real results directory or the wall clock.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from socagent import respond as R

AGENTS = {"win-victim": {"id": "001", "status": "active", "os": {"platform": "windows"}},
          "lin-victim": {"id": "002", "status": "disconnected", "os": {"platform": "ubuntu"}}}
STATUS_IDS = {"Done": 11, "Canceled": 12, "In progress": 13, "On hold": 14, "To do": 15}


def make_action(action="kill_process", target="1234", host="win-victim", executable=True, status="proposed",
                iris_case_id=None, id="act-1"):
    return R.Action(id=id, incident_id="INC-1", host=host, action=action, target=target, executable=executable,
                    reason="r", urgency="now", status=status, iris_case_id=iris_case_id,
                    proposed={"action": action, "host": host, "target": target, "reason": "r"})


class FakeClock:
    """Stand-in for the `time` module inside socagent.respond: sleep() advances monotonic()."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def hit(status="done", detail="killed 1234", ts="2026-11-14T10:00:00Z", agent="win-victim"):
    return {"_source": {"timestamp": ts, "agent": {"name": agent},
                        "data": {"command": "result", "parameters": {"action_id": "act-1", "status": status,
                                                                     "detail": detail}}}}


class FakeIx:
    """Indexer fake: returns no hits for the first `empty` searches, then `hits` (if any)."""

    def __init__(self, hits=None, empty=0):
        self.hits, self.empty, self.queries = hits or [], empty, []

    def search(self, index, q):
        self.queries.append((index, q))
        if len(self.queries) <= self.empty:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": list(self.hits)}}


class GateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name) / "response"
        self.dir = d
        for name, val in (("DIR", d), ("ACTIONS", d / "actions.json"), ("AUDIT", d / "audit.jsonl")):
            p = mock.patch.object(R, name, val)
            p.start(); self.addCleanup(p.stop)

        self.wazuh = mock.MagicMock(name="wazuh-instance")
        self.wazuh.agents.return_value = json.loads(json.dumps(AGENTS))
        self.wazuh.run.return_value = {"message": "AR command was sent to all agents",
                                       "data": {"affected_items": ["001"]}}
        p = mock.patch.object(R, "Wazuh", mock.MagicMock(name="Wazuh", return_value=self.wazuh))
        self.Wazuh = p.start(); self.addCleanup(p.stop)

        self.clock = FakeClock()
        p = mock.patch.object(R, "time", self.clock)
        p.start(); self.addCleanup(p.stop)

    def audit_lines(self):
        if not R.AUDIT.exists():
            return []
        return [json.loads(ln) for ln in R.AUDIT.read_text().splitlines() if ln.strip()]

    def audit_events(self):
        return [e["event"] for e in self.audit_lines()]

    def history_events(self, a):
        return [h["event"] for h in a.history]


# ------------------------------------------------------------------ execute
class ExecuteGuards(GateTest):
    def test_non_proposed_status_raises(self):
        for st in ("sent", "done", "rejected", "manual_done", "dispatch_failed", "failed", "refused"):
            a = make_action(status=st)
            with self.subTest(status=st), self.assertRaises(ValueError):
                R.execute(a, "alice", None)
            self.assertEqual(a.status, st)
        self.wazuh.run.assert_not_called()
        self.assertEqual(self.audit_events(), [])

    def test_manual_only_raises(self):
        a = make_action(action="reset_password", target="bob", executable=False)
        with self.assertRaises(ValueError) as cm:
            R.execute(a, "alice", None)
        self.assertIn("manual", str(cm.exception))
        self.assertEqual(a.status, "proposed")
        self.wazuh.run.assert_not_called()

    def test_target_edit_is_audited_and_applied(self):
        a = make_action(target="1234")
        R.execute(a, "alice", "  5678 ")
        self.assertEqual(a.target, "5678")
        lines = self.audit_lines()
        self.assertEqual(lines[0]["event"], "target_edited")
        self.assertEqual((lines[0]["old"], lines[0]["new"], lines[0]["by"]), ("1234", "5678", "alice"))
        self.assertEqual(a.history[0]["event"], "target_edited")
        self.assertEqual(self.wazuh.run.call_args.args[2], ["act-1", "kill_process", "5678"])

    def test_same_target_is_not_an_edit(self):
        a = make_action(target="1234")
        R.execute(a, "alice", "1234")
        self.assertNotIn("target_edited", self.audit_events())
        a = make_action(target="1234", id="act-2")
        R.execute(a, "alice", None)
        self.assertNotIn("target_edited", self.history_events(a))

    def test_invalid_edited_target_raises_before_wazuh(self):
        cases = [("kill_process", "1234", "x; rm -rf /"),
                 ("kill_process", "1234", "a|b"),
                 ("kill_process", "1234", "$(id)"),
                 ("block_ip", "192.0.2.10", "evil.example.com"),
                 ("block_ip", "192.0.2.10", "192.0.2"),
                 ("isolate_host", "30", "0"),
                 ("isolate_host", "30", "241"),
                 ("quarantine_file", r"C:\Users\Public\x.exe", "x.exe"),
                 ("kill_process", "1234", "   ")]
        for action, old, new in cases:
            a = make_action(action=action, target=old)
            with self.subTest(action=action, new=new), self.assertRaises(ValueError):
                R.execute(a, "alice", new)
            self.assertEqual(a.status, "proposed")
            self.assertIsNone(a.request)
        self.wazuh.run.assert_not_called()
        self.assertNotIn("approved", self.audit_events())
        self.assertNotIn("sent", self.audit_events())

    def test_invalid_original_target_raises(self):
        a = make_action(action="block_ip", target="not-an-ip")
        with self.assertRaises(ValueError):
            R.execute(a, "alice", None)
        self.wazuh.run.assert_not_called()

    def test_missing_agent_raises(self):
        a = make_action(host="sensor-gw")
        with self.assertRaises(ValueError):
            R.execute(a, "alice", None)
        self.assertEqual(a.status, "proposed")
        self.wazuh.run.assert_not_called()

    def test_inactive_agent_raises(self):
        a = make_action(host="lin-victim")
        with self.assertRaises(ValueError):
            R.execute(a, "alice", None)
        self.assertEqual(a.status, "proposed")
        self.assertIsNone(a.decided_by)
        self.wazuh.run.assert_not_called()
        self.assertNotIn("approved", self.audit_events())


class ExecuteSuccess(GateTest):
    def test_sent(self):
        a = make_action()
        out, follow = R.execute(a, "alice", None)
        self.assertIs(out, a)
        self.assertIsNone(follow)
        self.assertEqual(a.status, "sent")
        self.assertEqual(a.decided_by, "alice")
        self.assertTrue(a.decided_at)
        self.assertEqual(a.request, R.request_for(a, AGENTS["win-victim"]))
        self.assertEqual(a.request["body"]["arguments"], ["act-1", "kill_process", "1234"])
        self.assertIn("agents_list=001", a.request["path"])
        self.wazuh.run.assert_called_once_with("001", a.request["body"]["command"], ["act-1", "kill_process", "1234"])
        self.assertEqual(self.history_events(a), ["approved", "sent"])
        self.assertEqual(self.audit_events(), ["approved", "sent"])
        lines = self.audit_lines()
        self.assertEqual(lines[0]["by"], "alice")
        self.assertEqual(lines[0]["request"], a.request)
        self.assertTrue(all(ln["action_id"] == "act-1" for ln in lines))

    def test_linux_request_uses_shell_command(self):
        self.wazuh.agents.return_value["lin-victim"]["status"] = "active"
        a = make_action(host="lin-victim")
        R.execute(a, "alice", None)
        self.assertEqual(a.request["body"]["command"], "!tsoc-ar")
        self.assertEqual(a.request, R.request_for(a, self.wazuh.agents.return_value["lin-victim"]))

    def test_dispatch_failure(self):
        self.wazuh.run.side_effect = RuntimeError("Wazuh API PUT /active-response: 500 boom")
        a = make_action()
        iris = mock.MagicMock()
        ix = FakeIx(hits=[hit()])
        out, follow = R.execute(a, "alice", None, ix=ix, iris=iris)
        self.assertIs(out, a)
        self.assertIsNone(follow)
        self.assertEqual(a.status, "dispatch_failed")
        self.assertIn("500 boom", a.result["detail"])
        self.assertEqual(self.audit_events(), ["approved", "dispatch_failed"])
        self.assertIn("500 boom", self.audit_lines()[-1]["error"])
        self.assertEqual(ix.queries, [], "must not verify an action that was never dispatched")

    def test_isolate_done_proposes_release(self):
        a = make_action(action="isolate_host", target="30", iris_case_id=7)
        ix = FakeIx(hits=[hit(status="done", detail="isolated")])
        out, follow = R.execute(a, "alice", None, ix=ix)
        self.assertEqual(out.status, "done")
        self.assertIsInstance(follow, R.Action)
        self.assertEqual(follow.action, "release_host")
        self.assertTrue(follow.executable)
        self.assertEqual(follow.target, "")
        self.assertEqual(follow.status, "proposed")
        self.assertEqual((follow.incident_id, follow.host, follow.iris_case_id), ("INC-1", "win-victim", 7))
        self.assertNotEqual(follow.id, a.id)
        self.assertIn("proposed", self.audit_events())
        # the follow-up passes validation with its empty target
        self.assertIsNone(R.validate(follow))

    def test_isolate_not_done_has_no_follow_up(self):
        for st in ("failed", "refused"):
            a = make_action(action="isolate_host", target="30", id=f"act-{st}")
            _, follow = R.execute(a, "alice", None, ix=FakeIx(hits=[hit(status=st)]))
            with self.subTest(status=st):
                self.assertEqual(a.status, st)
                self.assertIsNone(follow)
        a = make_action(action="isolate_host", target="30", id="act-sent")
        _, follow = R.execute(a, "alice", None)  # no ix -> stays 'sent'
        self.assertEqual(a.status, "sent")
        self.assertIsNone(follow)

    def test_non_isolate_done_has_no_follow_up(self):
        a = make_action(action="block_ip", target="192.0.2.10")
        _, follow = R.execute(a, "alice", None, ix=FakeIx(hits=[hit(status="done")]))
        self.assertEqual(a.status, "done")
        self.assertIsNone(follow)

    def test_execute_syncs_iris_when_given(self):
        a = make_action()
        with mock.patch.object(R, "sync_iris") as sync:
            R.execute(a, "alice", None)
            sync.assert_not_called()
            b = make_action(id="act-2")
            iris = object()
            R.execute(b, "alice", None, iris=iris)
            sync.assert_called_once_with(b, iris)


# ------------------------------------------------------------------ verify
class Verify(GateTest):
    def test_found(self):
        a = make_action(status="sent")
        ix = FakeIx(hits=[hit(status="refused", detail="protected process")], empty=2)
        R.verify(a, ix, timeout_s=90)
        self.assertEqual(a.status, "refused")
        self.assertEqual(a.result["status"], "refused")
        self.assertEqual(a.result["detail"], "protected process")
        self.assertEqual(a.result["reported_at"], "2026-11-14T10:00:00Z")
        self.assertEqual(a.result["agent"], "win-victim")
        self.assertEqual(self.audit_events(), ["verified"])
        self.assertEqual(self.audit_lines()[0]["result"]["status"], "refused")
        self.assertEqual(len(ix.queries), 3)
        self.assertTrue(self.clock.sleeps, "must sleep (patched) between polls")

    def test_query_filters_on_action_id(self):
        a = make_action(id="act-xyz", status="sent")
        ix = FakeIx(hits=[hit()])
        R.verify(a, ix, timeout_s=10)
        index, q = ix.queries[0]
        self.assertTrue(index.startswith("wazuh-"))
        filters = q["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.parameters.action_id": "act-xyz"}}, filters)

    def test_missing_status_defaults_to_failed(self):
        a = make_action(status="sent")
        h = hit(); del h["_source"]["data"]["parameters"]["status"]
        R.verify(a, FakeIx(hits=[h]), timeout_s=10)
        self.assertEqual(a.status, "failed")

    def test_timeout(self):
        a = make_action(status="sent")
        ix = FakeIx(hits=[])
        R.verify(a, ix, timeout_s=20)
        self.assertEqual(a.status, "sent")
        self.assertIn("20s", a.result["detail"])
        self.assertIn("no result", a.result["detail"])
        self.assertEqual(self.audit_events(), ["unverified"])
        self.assertEqual(self.history_events(a), ["unverified"])
        self.assertGreaterEqual(len(ix.queries), 1)
        self.assertGreaterEqual(sum(self.clock.sleeps), 20 - 4)


# ------------------------------------------------------------------ reject / manual_done
class Decisions(GateTest):
    def check(self, fn, status, event, field):
        a = make_action(executable=(fn is R.reject))
        out = fn(a, "bob", "because")
        self.assertIs(out, a)
        self.assertEqual(a.status, status)
        self.assertEqual(a.decided_by, "bob")
        self.assertTrue(a.decided_at)
        self.assertEqual(a.note, "because")
        self.assertEqual(self.audit_events(), [event])
        line = self.audit_lines()[0]
        self.assertEqual((line["by"], line[field], line["action_id"]), ("bob", "because", "act-1"))
        self.assertEqual(self.history_events(a), [event])
        self.wazuh.run.assert_not_called()

    def test_reject(self):
        self.check(R.reject, "rejected", "rejected", "reason")

    def test_manual_done(self):
        self.check(R.manual_done, "manual_done", "manual_done", "note")

    def test_guards(self):
        for fn in (R.reject, R.manual_done):
            for st in ("sent", "done", "rejected", "manual_done", "dispatch_failed"):
                a = make_action(status=st)
                with self.subTest(fn=fn.__name__, status=st), self.assertRaises(ValueError):
                    fn(a, "bob", "x")
                self.assertEqual(a.status, st)
                self.assertIsNone(a.decided_by)
        self.assertEqual(self.audit_events(), [])

    def test_sync_iris_only_when_given(self):
        for fn in (R.reject, R.manual_done):
            with self.subTest(fn=fn.__name__), mock.patch.object(R, "sync_iris") as sync:
                fn(make_action(), "bob", "x")
                sync.assert_not_called()
                iris = object()
                a = make_action(id="act-2")
                fn(a, "bob", "x", iris=iris)
                sync.assert_called_once_with(a, iris)


# ------------------------------------------------------------------ sync_iris
class FakeIris:
    def __init__(self, tasks, wrap=False, fail=None):
        self.tasks, self.wrap, self.fail = tasks, wrap, fail
        self._call = mock.MagicMock(side_effect=self._do_call)
        self.lookup = mock.MagicMock(side_effect=lambda kind: dict(STATUS_IDS))

    def _do_call(self, method, path, body=None, cid=None):
        if self.fail:
            raise self.fail
        if method == "GET":
            return {"tasks": self.tasks} if self.wrap else self.tasks
        return {"status": "success"}

    def posts(self):
        return [c for c in self._call.call_args_list if c.args[0] == "POST"]


def title(a):
    p = a.proposed
    return f"[approve?] {p['action']} on {p['host']}: {p['target']}"


class SyncIris(GateTest):
    def tasks_for(self, a):
        return [{"task_id": 5, "task_title": "[approve?] something else"},
                {"task_id": 9, "task_title": title(a)}]

    def test_no_case_no_calls(self):
        for cid in (None, 0):
            a = make_action(iris_case_id=cid, status="done")
            iris = FakeIris(self.tasks_for(a))
            R.sync_iris(a, iris)
            iris._call.assert_not_called()
            iris.lookup.assert_not_called()
        self.assertEqual(self.audit_events(), [])

    def test_status_mapping(self):
        mapping = {"done": "Done", "manual_done": "Done", "rejected": "Canceled", "sent": "In progress",
                   "failed": "On hold", "refused": "On hold", "dispatch_failed": "On hold"}
        for i, (st, label) in enumerate(mapping.items()):
            for wrap in (False, True):
                a = make_action(id=f"act-{i}-{wrap}", status=st, iris_case_id=3)
                a.decided_by, a.decided_at = "alice", "2026-11-14T10:00:00+00:00"
                iris = FakeIris(self.tasks_for(a), wrap=wrap)
                R.sync_iris(a, iris)
                with self.subTest(status=st, wrapped=wrap):
                    get = iris._call.call_args_list[0]
                    self.assertEqual(get.args[:2], ("GET", "/case/tasks/list"))
                    self.assertEqual(get.kwargs.get("cid"), 3)
                    iris.lookup.assert_called_with("task-status")
                    posts = iris.posts()
                    self.assertEqual(len(posts), 2)
                    upd, com = posts
                    self.assertEqual(upd.args[1], "/case/tasks/status/update/9")
                    self.assertEqual(upd.args[2], {"task_status_id": STATUS_IDS[label]})
                    self.assertEqual(upd.kwargs.get("cid"), 3)
                    self.assertEqual(com.args[1], "/case/tasks/9/comments/add")
                    self.assertIn(st.upper(), com.args[2]["comment_text"])
                    self.assertIn("alice", com.args[2]["comment_text"])
                    self.assertEqual(com.kwargs.get("cid"), 3)
                    last = a.history[-1]
                    self.assertEqual((last["event"], last["task_id"], last["status"]), ("iris_synced", 9, label))

    def test_title_uses_original_proposal_after_target_edit(self):
        a = make_action(status="sent", iris_case_id=3, target="1234")
        a.target = "5678"   # approver edited the target; the IRIS task still carries the proposal's title
        iris = FakeIris(self.tasks_for(a))
        R.sync_iris(a, iris)
        self.assertEqual(len(iris.posts()), 2)
        self.assertEqual(iris.posts()[0].args[1], "/case/tasks/status/update/9")

    def test_comment_includes_result_and_note(self):
        a = make_action(status="done", iris_case_id=3)
        a.decided_by, a.decided_at, a.note = "alice", "t", "all good"
        a.request = {"method": "PUT"}
        a.result = {"status": "done", "detail": "killed 1234"}
        iris = FakeIris(self.tasks_for(a))
        R.sync_iris(a, iris)
        text = iris.posts()[1].args[2]["comment_text"]
        self.assertIn("killed 1234", text)
        self.assertIn("all good", text)
        self.assertIn("1234", text)

    def test_no_matching_task(self):
        a = make_action(status="done", iris_case_id=3)
        for wrap in (False, True):
            iris = FakeIris([{"task_id": 5, "task_title": "[approve?] kill_process on win-victim: 999"}], wrap=wrap)
            R.sync_iris(a, iris)
            self.assertEqual(iris.posts(), [])
        iris = FakeIris([])
        R.sync_iris(a, iris)
        self.assertEqual(iris.posts(), [])
        self.assertNotIn("iris_synced", self.audit_events())

    def test_failure_is_swallowed_and_audited(self):
        a = make_action(status="done", iris_case_id=3)
        iris = FakeIris(self.tasks_for(a), fail=RuntimeError("IRIS down"))
        R.sync_iris(a, iris)  # must not raise
        self.assertEqual(self.audit_events(), ["iris_sync_failed"])
        self.assertIn("IRIS down", self.audit_lines()[0]["error"])
        self.assertEqual(a.status, "done")

    def test_failure_on_post_is_swallowed(self):
        a = make_action(status="rejected", iris_case_id=3)
        iris = FakeIris(self.tasks_for(a))
        orig = iris._call.side_effect

        def boom(method, *args, **kw):
            if method == "POST":
                raise ConnectionError("reset")
            return orig(method, *args, **kw)
        iris._call.side_effect = boom
        R.sync_iris(a, iris)
        self.assertEqual(self.audit_events(), ["iris_sync_failed"])

    def test_reject_with_iris_updates_task(self):
        a = make_action(iris_case_id=3)
        iris = FakeIris(self.tasks_for(a))
        R.reject(a, "bob", "false positive", iris=iris)
        self.assertEqual(iris.posts()[0].args[2], {"task_status_id": STATUS_IDS["Canceled"]})
        self.assertIn("false positive", iris.posts()[1].args[2]["comment_text"])
        self.assertEqual(self.audit_events(), ["rejected", "iris_synced"])


# ------------------------------------------------------------------ persistence + audit
class Persistence(GateTest):
    def test_load_empty_when_missing(self):
        self.assertFalse(R.ACTIONS.exists())
        self.assertEqual(R.load(), [])

    def test_save_load_round_trip(self):
        a = make_action(iris_case_id=4)
        R.audit("proposed", a, by="test")
        a.status, a.request, a.result = "done", {"method": "PUT"}, {"status": "done", "detail": "ök"}
        b = make_action(action="reset_password", target="bob", executable=False, id="act-2")
        R.save([a, b])
        self.assertTrue(R.ACTIONS.exists())
        self.assertTrue(str(R.ACTIONS).startswith(str(self.dir)))
        loaded = R.load()
        self.assertEqual(loaded, [a, b])
        self.assertIsInstance(loaded[0], R.Action)
        self.assertEqual(loaded[0].history[0]["event"], "proposed")
        R.save([])
        self.assertEqual(R.load(), [])

    def test_audit_appends_one_json_line_per_event(self):
        a = make_action()
        R.audit("proposed", a, by="x")
        R.audit("approved", a, by="alice", request={"k": 1})
        R.audit("sent", a)
        raw = R.AUDIT.read_text().splitlines()
        self.assertEqual(len(raw), 3)
        lines = [json.loads(ln) for ln in raw]
        for ln, ev in zip(lines, ("proposed", "approved", "sent")):
            self.assertEqual(ln["event"], ev)
            self.assertEqual(ln["action_id"], "act-1")
            self.assertTrue(ln["ts"])
        self.assertEqual(lines[1]["request"], {"k": 1})
        self.assertEqual(self.history_events(a), ["proposed", "approved", "sent"])


if __name__ == "__main__":
    unittest.main()
