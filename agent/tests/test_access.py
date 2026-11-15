"""Tests for socagent.access: hash-only token storage, guests, expiry, daily caps, rate limit, spend report.
Run: cd agent && uv run pytest

access.DIR, access.TOKENS, access.SPEND and access.OWNER_FILE are always patched into a temporary
directory and access._hits is cleared, so lab/.secrets and results/ are never read or written
(every test also checks that the real files are unchanged). No network or LLM is involved.
"""
import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from socagent import access as A

REAL_PATHS = (A.DIR, A.TOKENS, A.SPEND, A.OWNER_FILE)


def sha(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def snapshot(paths):
    out = {}
    for p in paths:
        try:
            s = p.stat()
            out[str(p)] = (True, s.st_mtime_ns, s.st_size)
        except FileNotFoundError:
            out[str(p)] = (False, None, None)
    return out


def utc_ts(days_ago=0, hour=None):
    """ISO UTC timestamp `days_ago` days back (same time of day, or at `hour`)."""
    t = datetime.now(timezone.utc) - timedelta(days=days_ago)
    if hour is not None:
        t = t.replace(hour=hour, minute=0, second=0, microsecond=0)
    return t.isoformat(timespec="seconds")


class AccessTestBase(unittest.TestCase):
    def setUp(self):
        self._real_before = snapshot(REAL_PATHS)
        self.addCleanup(self._check_real_paths_untouched)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.dir = self.tmp / "console"
        for attr, val in (("DIR", self.dir), ("TOKENS", self.dir / "tokens.json"),
                          ("SPEND", self.dir / "spend.jsonl"), ("OWNER_FILE", self.tmp / "console-owner-token")):
            p = mock.patch.object(A, attr, val)
            p.start()
            self.addCleanup(p.stop)
        A._hits.clear()
        self.addCleanup(A._hits.clear)

    def _check_real_paths_untouched(self):
        self.assertEqual(snapshot(REAL_PATHS), self._real_before, "real results/ or lab/.secrets paths were touched")

    # helpers
    def tokens_raw(self):
        return A.TOKENS.read_text()

    def tokens_json(self):
        return json.loads(self.tokens_raw())

    def write_tokens(self, d):
        A.DIR.mkdir(parents=True, exist_ok=True)
        A.TOKENS.write_text(json.dumps(d))

    def write_spend(self, rows):
        A.DIR.mkdir(parents=True, exist_ok=True)
        with A.SPEND.open("a") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    def set_expires(self, tok, expires):
        d = A._load()
        d[sha(tok)].expires = expires
        A._save(d)


class TestIsolation(AccessTestBase):
    def test_paths_patched_into_tempdir(self):
        for p in (A.DIR, A.TOKENS, A.SPEND, A.OWNER_FILE):
            self.assertTrue(str(p).startswith(str(self.tmp)), p)
        self.assertEqual(A.TOKENS, A.DIR / "tokens.json")
        self.assertEqual(A.SPEND, A.DIR / "spend.jsonl")
        self.assertEqual(A._hits, {})

    def test_writes_land_in_tempdir(self):
        A.ensure_owner(); A.add_guest("alice", 1.0); A.record("alice", "ask", 0.01, "owner", {})
        self.assertTrue(A.TOKENS.exists())
        self.assertTrue(A.SPEND.exists())
        self.assertTrue(A.OWNER_FILE.exists())


class TestHashOnlyStorage(AccessTestBase):
    def test_raw_tokens_not_stored_hashes_are_keys(self):
        own = A.ensure_owner()
        g1 = A.add_guest("alice", 1.0)
        g2 = A.add_guest("bob", 0.5, days=3)
        raw = self.tokens_raw()
        for tok in (own, g1, g2):
            self.assertNotIn(tok, raw)
            # also not the random part without its prefix
            self.assertNotIn(tok.split("_", 1)[1], raw)
        self.assertEqual(set(self.tokens_json()), {sha(own), sha(g1), sha(g2)})
        for k in self.tokens_json():
            self.assertRegex(k, r"^[0-9a-f]{64}$")

    def test_token_prefixes(self):
        self.assertTrue(A.ensure_owner().startswith("own_"))
        self.assertTrue(A.add_guest("alice", 1.0).startswith("gst_"))

    def test_owner_file_holds_owner_token_mode_600(self):
        own = A.ensure_owner()
        self.assertEqual(A.OWNER_FILE.read_text().strip(), own)
        self.assertEqual(stat.S_IMODE(os.stat(A.OWNER_FILE).st_mode), 0o600)

    def test_tokens_json_mode_600(self):
        A.ensure_owner()
        self.assertEqual(stat.S_IMODE(os.stat(A.TOKENS).st_mode), 0o600)
        A.add_guest("alice", 1.0)
        self.assertEqual(stat.S_IMODE(os.stat(A.TOKENS).st_mode), 0o600)
        A.revoke("alice")
        self.assertEqual(stat.S_IMODE(os.stat(A.TOKENS).st_mode), 0o600)


class TestGuestsAndAuth(AccessTestBase):
    def test_new_guest_authenticates(self):
        tok = A.add_guest("alice", 0.75)
        p = A.authenticate(tok)
        self.assertIsInstance(p, A.Principal)
        self.assertEqual((p.name, p.role, p.daily_cap_usd, p.revoked), ("alice", "guest", 0.75, False))

    def test_none_empty_unknown_give_none(self):
        A.ensure_owner(); A.add_guest("alice", 1.0)
        self.assertIsNone(A.authenticate(None))
        self.assertIsNone(A.authenticate(""))
        self.assertIsNone(A.authenticate("gst_not-a-real-token"))

    def test_authenticate_with_no_tokens_file(self):
        self.assertFalse(A.TOKENS.exists())
        self.assertIsNone(A.authenticate("gst_anything"))
        self.assertEqual(A.principals(), [])

    def test_hash_itself_is_not_a_token(self):
        tok = A.add_guest("alice", 1.0)
        self.assertIsNone(A.authenticate(sha(tok)))

    def test_duplicate_active_name_refused(self):
        A.add_guest("alice", 1.0)
        with self.assertRaises(SystemExit):
            A.add_guest("alice", 2.0)
        self.assertEqual([p.name for p in A.principals()], ["alice"])

    def test_revoke_then_readd(self):
        tok = A.add_guest("alice", 1.0)
        other = A.add_guest("bob", 1.0)
        self.assertEqual(A.revoke("alice"), 1)
        self.assertIsNone(A.authenticate(tok))
        self.assertIsNotNone(A.authenticate(other), "revoking alice must not affect bob")
        tok2 = A.add_guest("alice", 2.0)
        self.assertNotEqual(tok, tok2)
        p = A.authenticate(tok2)
        self.assertEqual((p.name, p.daily_cap_usd), ("alice", 2.0))
        self.assertIsNone(A.authenticate(tok), "old revoked token must stay dead after re-add")

    def test_revoke_unknown_and_twice(self):
        A.add_guest("alice", 1.0)
        self.assertEqual(A.revoke("nobody"), 0)
        self.assertEqual(A.revoke("alice"), 1)
        self.assertEqual(A.revoke("alice"), 0)

    def test_ensure_owner_idempotent(self):
        t1 = A.ensure_owner()
        t2 = A.ensure_owner()
        self.assertEqual(t1, t2)
        owners = [p for p in A.principals() if p.role == "owner"]
        self.assertEqual(len(owners), 1)
        p = A.authenticate(t1)
        self.assertEqual((p.name, p.role), ("owner", "owner"))

    def test_ensure_owner_reuses_existing_file(self):
        A.OWNER_FILE.write_text("own_preexisting\n")
        self.assertEqual(A.ensure_owner(), "own_preexisting")
        self.assertEqual(A.authenticate("own_preexisting").role, "owner")


class TestExpiry(AccessTestBase):
    def test_days_sets_future_expiry_and_authenticates(self):
        tok = A.add_guest("alice", 1.0, days=30)
        p = A.authenticate(tok)
        self.assertIsNotNone(p)
        exp = datetime.fromisoformat(p.expires)
        now = datetime.now(timezone.utc)
        self.assertGreater(exp, now + timedelta(days=29))
        self.assertLessEqual(exp, now + timedelta(days=30, minutes=1))
        self.assertFalse(A.expired(p))

    def test_no_days_never_expires(self):
        tok = A.add_guest("alice", 1.0)
        p = A.authenticate(tok)
        self.assertIsNotNone(p)
        self.assertIsNone(p.expires)
        self.assertFalse(A.expired(p))

    def test_past_expiry_refused_and_does_not_block_readd(self):
        tok = A.add_guest("alice", 1.0, days=1)
        self.set_expires(tok, utc_ts(days_ago=1))
        self.assertIsNone(A.authenticate(tok))
        self.assertTrue(A.expired(A._load()[sha(tok)]))
        tok2 = A.add_guest("alice", 1.0)
        self.assertIsNotNone(A.authenticate(tok2))
        self.assertIsNone(A.authenticate(tok))

    def test_expiry_exactly_now_is_expired(self):
        p = A.Principal("g", "guest", 1.0, utc_ts(), expires=utc_ts())
        with mock.patch.object(A, "datetime", wraps=datetime) as dt:
            dt.now.return_value = datetime.fromisoformat(p.expires)
            dt.fromisoformat.side_effect = datetime.fromisoformat
            self.assertTrue(A.expired(p))

    def test_expiry_shortly_in_future_not_expired(self):
        p = A.Principal("g", "guest", 1.0, utc_ts(),
                        expires=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds"))
        self.assertFalse(A.expired(p))

    def test_old_format_without_expires_key(self):
        tok = "gst_handwritten-old-format"
        own = "own_handwritten-old-owner"
        self.write_tokens({
            sha(tok): {"name": "legacy", "role": "guest", "daily_cap_usd": 0.5, "created": "2026-01-01T00:00:00+00:00",
                       "revoked": False},
            sha(own): {"name": "owner", "role": "owner", "daily_cap_usd": 0.0, "created": "2026-01-01T00:00:00+00:00",
                       "revoked": False},
        })
        ps = {p.name: p for p in A.principals()}
        self.assertEqual(set(ps), {"legacy", "owner"})
        self.assertIsNone(ps["legacy"].expires)
        p = A.authenticate(tok)
        self.assertEqual((p.name, p.role, p.daily_cap_usd), ("legacy", "guest", 0.5))
        self.assertEqual(A.authenticate(own).role, "owner")
        # and a new guest can still be added next to the old entries
        self.assertIsNotNone(A.authenticate(A.add_guest("new", 1.0)))

    def test_owner_with_past_expires_never_expired(self):
        own = A.ensure_owner()
        self.set_expires(own, utc_ts(days_ago=100))
        p = A._load()[sha(own)]
        self.assertFalse(A.expired(p))
        self.assertEqual(A.authenticate(own).role, "owner")

    def test_days_zero_or_negative_refused(self):
        for days in (0, -1):
            with self.assertRaises(SystemExit):
                A.add_guest("alice", 1.0, days=days)
        self.assertEqual(A.principals(), [], "a refused add_guest must not store anything")


class TestDailyCap(AccessTestBase):
    def setUp(self):
        super().setUp()
        self.write_spend([
            {"ts": utc_ts(0), "principal": "alice", "kind": "ask", "cost_usd": 0.10, "billed_to": "owner"},
            {"ts": utc_ts(0), "principal": "alice", "kind": "ask", "cost_usd": 0.05, "billed_to": "owner"},
            {"ts": utc_ts(0), "principal": "alice", "kind": "ask", "cost_usd": 0.70, "billed_to": "byo"},
            {"ts": utc_ts(1), "principal": "alice", "kind": "ask", "cost_usd": 0.90, "billed_to": "owner"},
            {"ts": utc_ts(0), "principal": "bob", "kind": "ask", "cost_usd": 0.20, "billed_to": "owner"},
            {"ts": utc_ts(1), "principal": "bob", "kind": "ask", "cost_usd": 0.40, "billed_to": "byo"},
        ])

    def test_spent_today_only_today_owner_billed_by_name(self):
        self.assertAlmostEqual(A.spent_today("alice"), 0.15)
        self.assertAlmostEqual(A.spent_today("bob"), 0.20)
        self.assertEqual(A.spent_today("carol"), 0.0)

    def test_spent_today_no_file(self):
        A.SPEND.unlink()
        self.assertEqual(A.spent_today("alice"), 0.0)

    def test_record_appends_and_counts(self):
        A.record("carol", "ask", 0.123456, "owner", {"q": "x"})
        A.record("carol", "ask", 0.5, "byo", {})
        last = [json.loads(l) for l in A.SPEND.read_text().splitlines()][-2:]
        self.assertEqual(last[0]["principal"], "carol")
        self.assertEqual(last[0]["billed_to"], "owner")
        self.assertEqual(last[0]["q"], "x")
        self.assertAlmostEqual(last[0]["cost_usd"], 0.12346)
        self.assertEqual(last[0]["ts"][:10], datetime.now(timezone.utc).date().isoformat())
        self.assertAlmostEqual(A.spent_today("carol"), 0.12346)

    def test_budget_guest_capped_at_030(self):
        p = A.Principal("alice", "guest", 1.00, utc_ts())
        left, reason = A.budget_for(p, byo=False)
        self.assertIsNone(reason)
        self.assertAlmostEqual(left, 0.30)          # 1.00 - 0.15 = 0.85 -> capped to 0.30

    def test_budget_guest_remainder_below_030(self):
        p = A.Principal("alice", "guest", 0.25, utc_ts())
        left, reason = A.budget_for(p, byo=False)
        self.assertIsNone(reason)
        self.assertAlmostEqual(left, 0.10)          # 0.25 - 0.15; byo 0.70 and yesterday's 0.90 ignored

    def test_byo_spend_does_not_reduce_cap(self):
        before = A.budget_for(A.Principal("bob", "guest", 0.40, utc_ts()), byo=False)
        A.record("bob", "ask", 5.0, "byo", {})
        after = A.budget_for(A.Principal("bob", "guest", 0.40, utc_ts()), byo=False)
        self.assertEqual(before, after)
        self.assertAlmostEqual(after[0], 0.20)

    def test_budget_refused_when_cap_used(self):
        p = A.Principal("alice", "guest", 0.15, utc_ts())   # exactly used up
        left, reason = A.budget_for(p, byo=False)
        self.assertIsNone(left)
        self.assertIsInstance(reason, str)
        self.assertIn("0.15", reason)
        A.record("alice", "ask", 0.50, "owner", {})          # over the cap
        left, reason = A.budget_for(p, byo=False)
        self.assertIsNone(left)
        self.assertIn("$0.15", reason)

    def test_budget_threshold_half_cent(self):
        # remainder <= 0.005 is refused; clearly above it is allowed (values chosen away from float rounding)
        left, reason = A.budget_for(A.Principal("alice", "guest", 0.154, utc_ts()), byo=False)   # 0.004 left
        self.assertIsNone(left)
        self.assertIsNotNone(reason)
        left, reason = A.budget_for(A.Principal("alice", "guest", 0.16, utc_ts()), byo=False)    # 0.01 left
        self.assertIsNone(reason)
        self.assertAlmostEqual(left, 0.01)

    def test_budget_byo_ignores_cap(self):
        p = A.Principal("alice", "guest", 0.10, utc_ts())    # cap used up
        self.assertIsNone(A.budget_for(p, byo=False)[0])
        self.assertEqual(A.budget_for(p, byo=True), (1.00, None))

    def test_budget_owner(self):
        own = A.ensure_owner()
        A.record("owner", "ask", 50.0, "owner", {})
        self.assertEqual(A.budget_for(A.authenticate(own), byo=False), (1.00, None))
        self.assertEqual(A.budget_for(A.authenticate(own), byo=True), (1.00, None))


class TestRateLimit(AccessTestBase):
    def setUp(self):
        super().setUp()
        self.clock = 1000.0
        p = mock.patch.object(A.time, "monotonic", side_effect=lambda: self.clock)
        p.start()
        self.addCleanup(p.stop)

    def test_six_then_refused(self):
        self.assertEqual(A.RATE_PER_MIN, 6)
        self.assertEqual([A.rate_ok("alice") for _ in range(6)], [True] * 6)
        self.assertFalse(A.rate_ok("alice"))
        self.assertFalse(A.rate_ok("alice"))

    def test_names_independent(self):
        for _ in range(6):
            A.rate_ok("alice")
        self.assertFalse(A.rate_ok("alice"))
        self.assertEqual([A.rate_ok("bob") for _ in range(6)], [True] * 6)
        self.assertFalse(A.rate_ok("bob"))

    def test_resets_after_60s(self):
        for _ in range(6):
            self.assertTrue(A.rate_ok("alice"))
        self.assertFalse(A.rate_ok("alice"))
        self.clock += 59.0
        self.assertFalse(A.rate_ok("alice"), "still inside the 60 s window")
        self.clock += 1.5                              # 60.5 s after the first calls
        self.assertEqual([A.rate_ok("alice") for _ in range(6)], [True] * 6)
        self.assertFalse(A.rate_ok("alice"))

    def test_sliding_window(self):
        for i in range(6):
            self.clock = 1000.0 + i * 10              # calls at 1000, 1010, ..., 1050
            self.assertTrue(A.rate_ok("alice"))
        self.clock = 1055.0
        self.assertFalse(A.rate_ok("alice"))
        self.clock = 1060.5                           # only the call at 1000 has aged out
        self.assertTrue(A.rate_ok("alice"))
        self.assertFalse(A.rate_ok("alice"))

    def test_refused_calls_do_not_count(self):
        for _ in range(6):
            A.rate_ok("alice")
        self.clock += 30
        for _ in range(10):
            self.assertFalse(A.rate_ok("alice"))
        self.clock += 31                               # 61 s after the six allowed calls
        self.assertTrue(A.rate_ok("alice"))


class TestSpendReport(AccessTestBase):
    def setUp(self):
        super().setUp()
        self.today = datetime.now(timezone.utc).date()

    def day(self, n):
        return (self.today - timedelta(days=n)).isoformat()

    def test_empty(self):
        self.assertEqual(A.spend_report(), [])

    def test_window_split_and_caps(self):
        A.add_guest("alice", 0.50)
        A.ensure_owner()
        self.write_spend([
            {"ts": utc_ts(0, 1), "principal": "alice", "kind": "ask", "cost_usd": 0.10, "billed_to": "owner"},
            {"ts": utc_ts(0, 2), "principal": "alice", "kind": "ask", "cost_usd": 0.05, "billed_to": "owner"},
            {"ts": utc_ts(0, 3), "principal": "alice", "kind": "ask", "cost_usd": 0.30, "billed_to": "byo"},
            {"ts": utc_ts(2, 4), "principal": "alice", "kind": "ask", "cost_usd": 0.20, "billed_to": "byo"},
            {"ts": utc_ts(6, 5), "principal": "owner", "kind": "ask", "cost_usd": 0.70, "billed_to": "owner"},
            {"ts": utc_ts(7, 6), "principal": "alice", "kind": "ask", "cost_usd": 9.99, "billed_to": "owner"},
            {"ts": utc_ts(30, 6), "principal": "owner", "kind": "ask", "cost_usd": 9.99, "billed_to": "owner"},
            {"ts": utc_ts(1, 7), "principal": "ghost", "kind": "ask", "cost_usd": 0.01, "billed_to": "owner"},
        ])
        rows = A.spend_report(days=7)
        by = {(r["day"], r["name"]): r for r in rows}
        self.assertEqual(set(by), {(self.day(0), "alice"), (self.day(2), "alice"), (self.day(6), "owner"),
                                   (self.day(1), "ghost")})
        t = by[(self.day(0), "alice")]
        self.assertAlmostEqual(t["owner_usd"], 0.15)
        self.assertAlmostEqual(t["byo_usd"], 0.30)
        self.assertEqual(t["cap_usd"], 0.50)
        d2 = by[(self.day(2), "alice")]
        self.assertEqual((d2["owner_usd"], d2["byo_usd"]), (0.0, 0.20))
        o = by[(self.day(6), "owner")]
        self.assertEqual((o["owner_usd"], o["byo_usd"], o["cap_usd"]), (0.70, 0.0, 0.0))
        self.assertIsNone(by[(self.day(1), "ghost")]["cap_usd"], "no matching principal -> no cap")
        self.assertEqual([(r["day"], r["name"]) for r in rows], sorted(by), "rows sorted by (day, name)")

    def test_days_one_is_today_only(self):
        self.write_spend([
            {"ts": utc_ts(0, 1), "principal": "alice", "kind": "ask", "cost_usd": 0.10, "billed_to": "owner"},
            {"ts": utc_ts(1, 23), "principal": "alice", "kind": "ask", "cost_usd": 0.20, "billed_to": "owner"},
        ])
        rows = A.spend_report(days=1)
        self.assertEqual([(r["day"], r["name"], r["owner_usd"]) for r in rows], [(self.day(0), "alice", 0.10)])

    def test_cap_from_active_principal_after_readd(self):
        A.add_guest("alice", 0.50)
        A.revoke("alice")
        A.add_guest("alice", 2.00)
        self.write_spend([{"ts": utc_ts(0), "principal": "alice", "kind": "ask", "cost_usd": 0.1, "billed_to": "owner"}])
        (row,) = A.spend_report()
        self.assertEqual(row["cap_usd"], 2.00)

    def test_report_is_read_only(self):
        A.add_guest("alice", 0.50)
        self.write_spend([{"ts": utc_ts(0), "principal": "alice", "kind": "ask", "cost_usd": 0.1, "billed_to": "owner"}])
        before = (A.SPEND.read_bytes(), A.TOKENS.read_bytes())
        A.spend_report()
        self.assertEqual((A.SPEND.read_bytes(), A.TOKENS.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
