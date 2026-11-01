"""Grouping rules for socagent.incidents. Run: uv run --project agent python -m unittest discover -s agent/tests"""
import unittest

from socagent import incidents as I


def t(host, rule, first, last=None, verdict="malicious", esc=True, summary="", techs=()):
    return {"bundle_key": f"{host}|{rule}|{first}", "host": host, "rule_id": rule, "rule_description": f"rule {rule}",
            "max_level": 10, "alert_count": 1, "first": first, "last": last or first, "verdict": verdict,
            "confidence": 0.9, "escalate": esc, "attack_techniques": list(techs), "summary": summary,
            "key_evidence": [], "open_questions": [], "cost_usd": 0.001}


D = "2026-11-01T"


class Grouping(unittest.TestCase):
    def ids(self, rows):
        incs = I.group(rows, [])
        return sorted(sorted(i.bundle_keys) for i in incs), incs

    def test_same_host_within_gap_merges_transitively(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000"), t("win-victim", "2", D + "10:25:00+0000"),
                t("win-victim", "3", D + "10:50:00+0000")]  # 3 is 25 min after 2: chain holds
        groups, _ = self.ids(rows)
        self.assertEqual(len(groups), 1)

    def test_gap_over_30_minutes_splits(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000"), t("win-victim", "2", D + "10:31:00+0000")]
        groups, _ = self.ids(rows)
        self.assertEqual(len(groups), 2)

    def test_different_hosts_stay_apart(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000"), t("lin-victim", "2", D + "10:01:00+0000")]
        groups, _ = self.ids(rows)
        self.assertEqual(len(groups), 2)

    def test_network_alert_links_hosts_by_ip(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000"),
                t("sensor-gw", "86601", D + "10:02:00+0000", summary="beacon from 10.10.10.20 to 1.2.3.4"),
                t("lin-victim", "2", D + "10:03:00+0000")]
        groups, incs = self.ids(rows)
        self.assertEqual(len(groups), 2)                       # sensor alert joins win-victim only
        win = next(i for i in incs if "win-victim" in i.hosts)
        self.assertEqual(len(win.bundle_keys), 2)
        self.assertNotIn("sensor-gw", win.hosts)

    def test_admin_workstation_ip_does_not_link(self):
        rows = [t("sensor-gw", "100101", D + "10:00:00+0000", summary="RDP from 10.10.10.254 to 10.10.10.20"),
                t("lin-victim", "2", D + "10:01:00+0000", summary="ssh from 10.10.10.254")]
        groups, _ = self.ids(rows)
        self.assertEqual(len(groups), 2)

    def test_benign_not_escalated_is_ignored_and_latest_verdict_wins(self):
        a = t("win-victim", "1", D + "10:00:00+0000")
        a_rejudged = dict(a, verdict="benign", escalate=False)
        groups, _ = self.ids([a, a_rejudged])
        self.assertEqual(groups, [])

    def test_severity(self):
        self.assertEqual(I.severity([t("w", "1", D + "1", techs=["T1003.001"])]), "critical")
        self.assertEqual(I.severity([t("w", "1", D + "1", techs=["T1053.005"])]), "high")
        self.assertEqual(I.severity([t("w", "1", D + "1", verdict="suspicious", techs=["T1136.001"])]), "medium")

    def test_ids_are_stable_across_reruns(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000"), t("lin-victim", "2", D + "11:00:00+0000")]
        first = I.group(rows, [])
        first[0].status = "investigated"
        again = I.group(rows + [t("win-victim", "3", D + "10:10:00+0000")], first)
        by_host = {i.hosts[0]: i for i in again}
        self.assertEqual(by_host["win-victim"].id, first[0].id)
        self.assertEqual(by_host["win-victim"].status, "investigated")
        self.assertEqual(len({i.id for i in again}), 2)


if __name__ == "__main__":
    unittest.main()
