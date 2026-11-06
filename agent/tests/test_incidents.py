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


class InvestigationQueue(unittest.TestCase):
    def inc(self, id, severity, first, status="new"):
        return I.Incident(id=id, status=status, severity=severity, title=id, hosts=["win-victim"], first=D + first,
                          last=D + first, verdicts={}, techniques=[], max_level=10, bundle_keys=[id])

    def test_low_severity_is_left_out(self):
        queue = I.investigation_queue([self.inc("a", "critical", "10:00:00+0000"), self.inc("b", "medium", "09:00:00+0000")])
        self.assertEqual([i.id for i in queue], ["a"])

    def test_default_includes_high_and_excludes_medium(self):
        queue = I.investigation_queue([self.inc("h", "high", "10:00:00+0000"), self.inc("m", "medium", "09:00:00+0000"),
                                       self.inc("l", "low", "08:00:00+0000")])
        self.assertEqual([i.id for i in queue], ["h"])

    def test_explicit_min_severity_is_inclusive(self):
        queue = I.investigation_queue([self.inc("m", "medium", "10:00:00+0000"), self.inc("l", "low", "09:00:00+0000")],
                                      min_severity="medium")
        self.assertEqual([i.id for i in queue], ["m"])

    def test_most_severe_first_across_severities(self):
        queue = I.investigation_queue([self.inc("h", "high", "08:00:00+0000"), self.inc("c", "critical", "11:00:00+0000"),
                                       self.inc("m", "medium", "07:00:00+0000")], min_severity="medium")
        self.assertEqual([i.id for i in queue], ["c", "h", "m"])

    def test_oldest_first_compares_times_not_strings(self):
        # 10:30+01:00 is 09:30 UTC, earlier than 10:00+0000, though it sorts later as a string
        queue = I.investigation_queue([self.inc("b", "high", "10:00:00+0000"), self.inc("a", "high", "10:30:00+01:00")])
        self.assertEqual([i.id for i in queue], ["a", "b"])

    def test_only_new_incidents(self):
        queue = I.investigation_queue([self.inc("a", "critical", "10:00:00+0000", status="investigated"),
                                       self.inc("b", "critical", "11:00:00+0000")])
        self.assertEqual([i.id for i in queue], ["b"])

    def test_oldest_first_within_a_severity(self):
        queue = I.investigation_queue([self.inc("late", "critical", "11:00:00+0000"), self.inc("early", "critical", "09:00:00+0000")])
        self.assertEqual([i.id for i in queue], ["early", "late"])


class SeverityCounts(unittest.TestCase):
    def inc(self, id, severity):
        return I.Incident(id=id, status="new", severity=severity, title=id, hosts=["win-victim"],
                          first=D + "10:00:00+0000", last=D + "10:00:00+0000", verdicts={}, techniques=[],
                          max_level=10, bundle_keys=[id])

    def test_counts_each_severity(self):
        incs = [self.inc("a", "critical"), self.inc("b", "high"), self.inc("c", "high"), self.inc("d", "low")]
        self.assertEqual(I.severity_counts(incs), {"critical": 1, "high": 2, "medium": 0, "low": 1})

    def test_empty_input_is_all_zeros(self):
        self.assertEqual(I.severity_counts([]), {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_unused_severities_are_present_as_zero(self):
        counts = I.severity_counts([self.inc("a", "medium")])
        self.assertEqual(set(counts), set(I.SEVERITY_ORDER))
        self.assertEqual(counts["medium"], 1)
        self.assertEqual([counts[s] for s in ("critical", "high", "low")], [0, 0, 0])

    def test_total_matches_number_of_incidents(self):
        incs = [self.inc(str(n), s) for n, s in enumerate(["low", "low", "critical", "medium", "high", "low"])]
        self.assertEqual(sum(I.severity_counts(incs).values()), len(incs))
        self.assertEqual(I.severity_counts(incs)["low"], 3)

    def test_keys_are_ordered_most_severe_first(self):
        self.assertEqual(list(I.severity_counts([])), ["critical", "high", "medium", "low"])

    def test_status_is_ignored_unlike_the_queue(self):
        incs = [self.inc("a", "critical"), self.inc("b", "critical")]
        incs[0].status = "closed"
        self.assertEqual(I.severity_counts(incs)["critical"], 2)

    def test_unknown_severity_is_kept_not_dropped(self):
        counts = I.severity_counts([self.inc("a", "informational"), self.inc("b", "high")])
        self.assertEqual(counts["informational"], 1)
        self.assertEqual(sum(counts.values()), 2)

    def test_counts_incidents_built_by_group(self):
        rows = [t("win-victim", "1", D + "10:00:00+0000", techs=["T1003.001"]),   # critical
                t("lin-victim", "2", D + "11:00:00+0000", techs=["T1053.005"])]   # high
        self.assertEqual(I.severity_counts(I.group(rows, [])), {"critical": 1, "high": 1, "medium": 0, "low": 0})


if __name__ == "__main__":
    unittest.main()
