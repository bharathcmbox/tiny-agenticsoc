"""Tests for respond.py planning, target prefill, validation and request building.
Run: cd agent && uv run pytest

R.DIR / R.ACTIONS / R.AUDIT are redirected to a temporary directory for every test that plans,
saves, loads or audits, so the real results directory is never touched. Nothing here talks to the
network, Wazuh, the indexer or IRIS.
"""
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from socagent import respond as R


def action(kind, target, host="win-victim", **kw):
    return R.Action(id="act-000000000000", incident_id="INC-1", host=host, action=kind, target=target,
                    executable=True, reason="r", urgency="now", proposed={}, **kw)


class Prefill(unittest.TestCase):
    def pf(self, kind, target, report=None, host="win-victim"):
        return R._prefill(kind, target, report or {}, host)

    # quarantine_file
    def test_quarantine_absolute_windows_path_unchanged(self):
        self.assertEqual(self.pf("quarantine_file", "  C:\\x\\y.exe  "), "C:\\x\\y.exe")

    def test_quarantine_absolute_posix_path_unchanged(self):
        rep = {"iocs": [{"type": "file_path", "value": "/other/y"}]}
        self.assertEqual(self.pf("quarantine_file", " /tmp/y ", rep, host="lin-victim"), "/tmp/y")

    def test_quarantine_bare_name_uses_matching_ioc_backslash(self):
        rep = {"iocs": [{"type": "ip", "value": "10.0.0.1"},
                        {"type": "file_path", "value": "C:\\Users\\Public\\other.exe"},
                        {"type": "file_path", "value": "C:\\Users\\Public\\Evil.EXE"}]}
        self.assertEqual(self.pf("quarantine_file", "evil.exe", rep), "C:\\Users\\Public\\Evil.EXE")

    def test_quarantine_bare_name_uses_matching_ioc_forward_slash(self):
        rep = {"iocs": [{"type": "file_path", "value": "/tmp/payload.sh"}]}
        self.assertEqual(self.pf("quarantine_file", "PAYLOAD.sh", rep, host="lin-victim"), "/tmp/payload.sh")

    def test_quarantine_relative_path_matches_on_base_name(self):
        rep = {"iocs": [{"type": "file_path", "value": "C:\\Temp\\drop\\evil.exe"}]}
        self.assertEqual(self.pf("quarantine_file", "drop/evil.exe", rep), "C:\\Temp\\drop\\evil.exe")
        self.assertEqual(self.pf("quarantine_file", "'Temp\\drop\\evil.exe'", rep), "C:\\Temp\\drop\\evil.exe")

    def test_quarantine_ignores_non_file_path_iocs(self):
        rep = {"iocs": [{"type": "hash", "value": "C:\\x\\evil.exe"}]}
        self.assertEqual(self.pf("quarantine_file", "evil.exe", rep), "evil.exe")

    def test_quarantine_no_matching_ioc_returns_original(self):
        rep = {"iocs": [{"type": "file_path", "value": "C:\\x\\other.exe"}]}
        self.assertEqual(self.pf("quarantine_file", " evil.exe ", rep), "evil.exe")
        self.assertEqual(self.pf("quarantine_file", "evil.exe", {}), "evil.exe")

    # remove_persistence
    def test_persistence_windows_quoted_name(self):
        self.assertEqual(self.pf("remove_persistence", "Delete the scheduled task 'Updater Svc' now"), "Updater Svc")
        self.assertEqual(self.pf("remove_persistence", 'Run key "EvilRun"', host="win-dc"), "EvilRun")

    def test_persistence_windows_word_after_scheduled_task(self):
        self.assertEqual(self.pf("remove_persistence", "Scheduled Task tsoc-evil.v2 created by malware"), "tsoc-evil.v2")

    def test_persistence_windows_word_after_task(self):
        self.assertEqual(self.pf("remove_persistence", "remove task Backdoor_1"), "Backdoor_1")

    def test_persistence_linux_first_absolute_path(self):
        self.assertEqual(self.pf("remove_persistence", "cron file /etc/cron.d/foo and /etc/systemd/system/x.service",
                                 host="lin-victim"), "/etc/cron.d/foo")

    def test_persistence_linux_ignores_task_words_and_quotes(self):
        self.assertEqual(self.pf("remove_persistence", "task 'evil' in /etc/cron.d/evil", host="lin-victim"),
                         "/etc/cron.d/evil")

    def test_persistence_otherwise_returns_input(self):
        self.assertEqual(self.pf("remove_persistence", "  some crontab entry  ", host="lin-victim"), "some crontab entry")
        self.assertEqual(self.pf("remove_persistence", "registry run key", host="win-victim"), "registry run key")

    # disable_account
    def test_disable_account_strips_domain_and_quotes(self):
        self.assertEqual(self.pf("disable_account", "CORP\\alice"), "alice")
        self.assertEqual(self.pf("disable_account", "'CORP\\bob'"), "bob")
        self.assertEqual(self.pf("disable_account", ' "carol" '), "carol")
        self.assertEqual(self.pf("disable_account", "dave", host="lin-victim"), "dave")

    # block_ip
    def test_block_ip_extracts_ipv4(self):
        self.assertEqual(self.pf("block_ip", "C2 server at 203.0.113.45:443 (tcp)"), "203.0.113.45")

    def test_block_ip_without_ip_unchanged(self):
        self.assertEqual(self.pf("block_ip", " evil.example.com "), "evil.example.com")

    # isolate_host
    def test_isolate_host_always_30(self):
        for t in ("win-victim", "", "isolate for 120 minutes"):
            with self.subTest(t=t):
                self.assertEqual(self.pf("isolate_host", t), "30")

    # kill_process
    def test_kill_process_pid(self):
        self.assertEqual(self.pf("kill_process", "PID 4321"), "4321")
        self.assertEqual(self.pf("kill_process", "evil.exe (pid 4321)"), "4321")
        self.assertEqual(self.pf("kill_process", "pid:98765"), "98765")

    def test_kill_process_base_name(self):
        self.assertEqual(self.pf("kill_process", "C:\\Windows\\evil.exe -x"), "evil.exe")
        self.assertEqual(self.pf("kill_process", "/usr/bin/nc -lvp 4444", host="lin-victim"), "nc")
        self.assertEqual(self.pf("kill_process", "'mimikatz.exe'"), "mimikatz.exe")

    def test_kill_process_digits_without_pid_word_is_a_name(self):
        self.assertEqual(self.pf("kill_process", "C:\\x\\a1234.exe"), "a1234.exe")


class Validate(unittest.TestCase):
    def test_valid_targets(self):
        for kind, t in [("kill_process", "evil.exe"), ("kill_process", "4321"),
                        ("quarantine_file", "C:\\Users\\Public\\x.txt"), ("quarantine_file", "/tmp/x"),
                        ("quarantine_file", "c:\\x"), ("remove_persistence", "/etc/cron.d/foo"),
                        ("disable_account", "alice"), ("block_ip", "192.0.2.10"), ("block_ip", " 10.1.2.3 "),
                        ("isolate_host", "1"), ("isolate_host", "30"), ("isolate_host", "240"),
                        ("release_host", ""), ("release_host", "   ")]:
            with self.subTest(kind=kind, t=t):
                self.assertIsNone(R.validate(action(kind, t)))

    def test_empty_target(self):
        for kind in ("kill_process", "quarantine_file", "remove_persistence", "disable_account", "block_ip",
                     "isolate_host"):
            for t in ("", "   "):
                with self.subTest(kind=kind, t=t):
                    self.assertEqual(R.validate(action(kind, t)), "target is empty")

    def test_length_limit(self):
        self.assertIsNone(R.validate(action("kill_process", "a" * 260)))
        self.assertEqual(R.validate(action("kill_process", "a" * 261)),
                         "target contains characters that are not allowed")
        self.assertEqual(R.validate(action("quarantine_file", "C:\\" + "a" * 258)),
                         "target contains characters that are not allowed")

    def test_forbidden_characters(self):
        for c in "\n\r\0`$;|&<>":
            with self.subTest(c=repr(c)):
                self.assertEqual(R.validate(action("kill_process", f"evil{c}x.exe")),
                                 "target contains characters that are not allowed")
                self.assertEqual(R.validate(action("quarantine_file", f"/tmp/a{c}b")),
                                 "target contains characters that are not allowed")
                self.assertEqual(R.validate(action("release_host", f"x{c}y")),
                                 "target contains characters that are not allowed")

    def test_block_ip_needs_ipv4(self):
        for t in ("evil.example.com", "1.2.3", "1.2.3.4.5", "1.2.3.4/24", "2001:db8::1", "ip 1.2.3.4", "1.2.3.x"):
            with self.subTest(t=t):
                self.assertEqual(R.validate(action("block_ip", t)), "block_ip needs an IPv4 address")

    def test_isolate_host_minutes_range(self):
        for t in ("0", "241", "abc", "-5", "1.5", "30m"):
            with self.subTest(t=t):
                self.assertEqual(R.validate(action("isolate_host", t)), "isolate_host needs minutes (1-240)")

    def test_quarantine_needs_absolute_path(self):
        for t in ("evil.exe", "Users\\Public\\x", "./x", "C:x", "\\\\server\\share\\x"):
            with self.subTest(t=t):
                self.assertEqual(R.validate(action("quarantine_file", t)), "quarantine_file needs an absolute path")


class RequestFor(unittest.TestCase):
    def check(self, a, req, agent_id, command):
        self.assertEqual(req["path"], f"/active-response?agents_list={agent_id}")
        self.assertEqual(req["body"]["command"], command)
        self.assertEqual(req["body"]["arguments"], [a.id, a.action, a.target])

    def test_windows_by_platform(self):
        a = action("kill_process", "evil.exe", host="dc01")
        self.check(a, R.request_for(a, {"id": "007", "os": {"platform": "windows"}}), "007", "!tsoc-ar.cmd")

    def test_windows_by_host_name(self):
        a = action("block_ip", "192.0.2.10", host="win-victim")
        self.check(a, R.request_for(a, {"id": "001"}), "001", "!tsoc-ar.cmd")
        self.check(a, R.request_for(a, {"id": "001", "os": None}), "001", "!tsoc-ar.cmd")

    def test_linux(self):
        a = action("quarantine_file", "/tmp/x", host="lin-victim")
        self.check(a, R.request_for(a, {"id": "002", "os": {"platform": "ubuntu"}}), "002", "!tsoc-ar")
        b = action("block_ip", "192.0.2.10", host="sensor-gw")
        self.check(b, R.request_for(b, {"id": "003"}), "003", "!tsoc-ar")


def inc(id, investigation={"iris_case_id": 7}):
    return types.SimpleNamespace(id=id, investigation=investigation)


def prop(action, target, host="win-victim", reason="because", urgency="now"):
    return {"action": action, "host": host, "target": target, "reason": reason, "urgency": urgency}


class Plan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.resp = root / "response"
        self.inv = root / "investigations"
        self.inv.mkdir()
        for name, val in (("DIR", self.resp), ("ACTIONS", self.resp / "actions.json"),
                          ("AUDIT", self.resp / "audit.jsonl")):
            p = mock.patch.object(R, name, val)
            p.start()
            self.addCleanup(p.stop)

    def write(self, id, report):
        (self.inv / f"{id}.json").write_text(json.dumps({"report": report}))

    def audit_lines(self):
        if not R.AUDIT.exists():
            return []
        return [json.loads(ln) for ln in R.AUDIT.read_text().splitlines() if ln.strip()]

    def test_paths_are_redirected(self):
        self.assertTrue(str(R.ACTIONS).startswith(self._tmp.name))
        self.assertTrue(str(R.AUDIT).startswith(self._tmp.name))

    def test_skips_uninvestigated_missing_and_benign(self):
        p = [prop("kill_process", "PID 4321")]
        self.write("INC-NOINV", {"verdict": "malicious", "proposed_actions": p})
        self.write("INC-BENIGN", {"verdict": "benign", "proposed_actions": p})
        (self.inv / "INC-NOREPORT.json").write_text(json.dumps({"report": None}))
        out = R.plan([inc("INC-NOINV", None), inc("INC-NOINV2", {}), inc("INC-MISSING"), inc("INC-BENIGN"),
                      inc("INC-NOREPORT")], self.inv)
        self.assertEqual(out, [])
        self.assertEqual(R.load(), [])
        self.assertEqual(self.audit_lines(), [])

    def test_proposed_actions_become_actions(self):
        report = {"verdict": "malicious",
                  "iocs": [{"type": "file_path", "value": "C:\\Users\\Public\\evil.exe"}],
                  "proposed_actions": [prop("delete_file", "evil.exe", reason="dropper", urgency="now"),
                                       prop("kill_process", "PID 4321", urgency="soon"),
                                       prop("block_ip", "C2 at 203.0.113.9", host="sensor-gw"),
                                       prop("remove_persistence", "/etc/cron.d/evil", host="lin-victim")]}
        self.write("INC-1", report)
        out = R.plan([inc("INC-1", {"iris_case_id": 42})], self.inv)
        self.assertEqual(len(out), 4)
        self.assertEqual([(a.action, a.target, a.host) for a in out],
                         [("quarantine_file", "C:\\Users\\Public\\evil.exe", "win-victim"),
                          ("kill_process", "4321", "win-victim"),
                          ("block_ip", "203.0.113.9", "sensor-gw"),
                          ("remove_persistence", "/etc/cron.d/evil", "lin-victim")])
        for a, p in zip(out, report["proposed_actions"]):
            with self.subTest(a=a.action):
                self.assertEqual(a.status, "proposed")
                self.assertTrue(a.id.startswith("act-"))
                self.assertTrue(a.executable)
                self.assertEqual(a.incident_id, "INC-1")
                self.assertEqual(a.iris_case_id, 42)
                self.assertEqual(a.proposed, p)
                self.assertEqual(a.reason, p["reason"])
                self.assertEqual(a.urgency, p["urgency"])
        self.assertEqual(len({a.id for a in out}), 4)

    def test_iris_case_id_absent(self):
        self.write("INC-2", {"verdict": "suspicious", "proposed_actions": [prop("isolate_host", "win-victim")]})
        (a,) = R.plan([inc("INC-2", {"summary": "x"})], self.inv)
        self.assertIsNone(a.iris_case_id)
        self.assertEqual(a.target, "30")

    def test_unmapped_and_unknown_host_not_executable(self):
        self.write("INC-3", {"verdict": "malicious", "proposed_actions": [
            prop("notify_user", "  tell alice@corp  "),
            prop("kill_process", "PID 999", host="win-dc"),
            prop("block_ip", "1.2.3.4", host="firewall")]})
        notify, kill_other, block_other = R.plan([inc("INC-3")], self.inv)
        self.assertEqual((notify.action, notify.target, notify.executable), ("notify_user", "  tell alice@corp  ", False))
        self.assertEqual(notify.status, "proposed")
        self.assertEqual((kill_other.action, kill_other.target, kill_other.executable), ("kill_process", "999", False))
        self.assertEqual((block_other.action, block_other.executable), ("block_ip", False))

    def test_executable_hosts(self):
        hosts = ("win-victim", "lin-victim", "sensor-gw", "WIN-VICTIM", "win-victim2", "")
        self.write("INC-4", {"verdict": "malicious",
                             "proposed_actions": [prop("disable_account", f"u{i}", host=h) for i, h in enumerate(hosts)]})
        out = R.plan([inc("INC-4")], self.inv)
        self.assertEqual([a.executable for a in out], [True, True, True, False, False, False])

    def test_idempotent_and_audited_and_persisted(self):
        self.write("INC-5", {"verdict": "malicious", "proposed_actions": [
            prop("kill_process", "PID 4321"), prop("notify_user", "call the user")]})
        first = R.plan([inc("INC-5")], self.inv)
        self.assertEqual(len(first), 2)
        lines = self.audit_lines()
        self.assertEqual([ln["event"] for ln in lines], ["proposed", "proposed"])
        self.assertEqual([ln["action_id"] for ln in lines], [a.id for a in first])
        self.assertEqual({ln["incident"] for ln in lines}, {"INC-5"})
        loaded = R.load()
        self.assertEqual([(a.id, a.action, a.target, a.status) for a in loaded],
                         [(a.id, a.action, a.target, a.status) for a in first])

        second = R.plan([inc("INC-5")], self.inv)
        self.assertEqual([a.id for a in second], [a.id for a in first])
        self.assertEqual(len(R.load()), 2)
        self.assertEqual(len(self.audit_lines()), 2)

    def test_new_proposal_added_later_only_once(self):
        self.write("INC-6", {"verdict": "malicious", "proposed_actions": [prop("kill_process", "PID 1111")]})
        R.plan([inc("INC-6")], self.inv)
        self.write("INC-6", {"verdict": "malicious", "proposed_actions": [
            prop("kill_process", "PID 1111"), prop("block_ip", "198.51.100.7")]})
        out = R.plan([inc("INC-6")], self.inv)
        self.assertEqual([a.target for a in out], ["1111", "198.51.100.7"])
        self.assertEqual(len(self.audit_lines()), 2)
        R.plan([inc("INC-6")], self.inv)
        self.assertEqual(len(R.load()), 2)

    def test_same_proposal_in_two_incidents_is_two_actions(self):
        p = [prop("block_ip", "198.51.100.7")]
        self.write("INC-A", {"verdict": "malicious", "proposed_actions": p})
        self.write("INC-B", {"verdict": "malicious", "proposed_actions": p})
        out = R.plan([inc("INC-A"), inc("INC-B")], self.inv)
        self.assertEqual([a.incident_id for a in out], ["INC-A", "INC-B"])
        self.assertEqual(len(self.audit_lines()), 2)

    def test_plan_keeps_existing_actions(self):
        existing = action("block_ip", "192.0.2.1")
        R.save([existing])
        self.write("INC-7", {"verdict": "malicious", "proposed_actions": [prop("kill_process", "PID 22")]})
        out = R.plan([inc("INC-7")], self.inv)
        self.assertEqual([a.id for a in out][0], existing.id)
        self.assertEqual(len(R.load()), 2)


if __name__ == "__main__":
    unittest.main()
