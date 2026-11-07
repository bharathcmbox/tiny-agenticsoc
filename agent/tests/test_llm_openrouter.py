"""Tests for the OpenRouter tool-call and caching path in socagent.llm. Run: cd agent && uv run pytest

No network: every LLM gets a fake OpenRouter client whose chat.completions.create is a Mock with
scripted responses, every scripted usage carries `cost`, and `_openrouter_prices` (the only other
network fetch) is patched to fail the test if it is ever called.
"""
import json
import types
import unittest
from unittest import mock

import httpx
import openai

from socagent import llm as L

NS = types.SimpleNamespace

TOOL = {
    "name": "submit_verdict",
    "description": "Submit the triage verdict.",
    "input_schema": {"type": "object", "properties": {"verdict": {"type": "string"}},
                     "required": ["verdict"]},
}
NAME = TOOL["name"]

FORCING = "anthropic/claude-haiku-5.5"
NON_FORCING = "anthropic/claude-sonnet-5.5"
OTHER = "openai/gpt-5-mini"


def usage(prompt=100, completion=20, cached=0, written=None, cost=0.001):
    details = NS(cached_tokens=cached)
    if written is not None:
        details.cache_write_tokens = written
    return NS(prompt_tokens=prompt, completion_tokens=completion, prompt_tokens_details=details, cost=cost)


def tool_reply(args, finish="tool_calls", **u):
    call = NS(id="call_1", type="function", function=NS(name=NAME, arguments=json.dumps(args)))
    msg = NS(role="assistant", content=None, tool_calls=[call])
    return NS(choices=[NS(finish_reason=finish, message=msg)], usage=usage(**u))


def text_reply(text="I think it is benign.", finish="stop", **u):
    msg = NS(role="assistant", content=text, tool_calls=None)
    return NS(choices=[NS(finish_reason=finish, message=msg)], usage=usage(**u))


def bad_request(message, body=None):
    req = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    resp = httpx.Response(400, request=req)
    return openai.BadRequestError(message, response=resp, body=body)


class OpenRouterBase(unittest.TestCase):
    def setUp(self):
        prices = mock.patch("socagent.llm._openrouter_prices",
                            side_effect=AssertionError("_openrouter_prices must not be called (network)"))
        self.prices = prices.start()
        self.addCleanup(prices.stop)
        # Belt and braces: constructing a real OpenAI client would also be a test bug.
        real = mock.patch("openai.OpenAI", side_effect=AssertionError("real OpenAI client constructed"))
        real.start()
        self.addCleanup(real.stop)

    def make(self, *responses):
        """An LLM whose fake OpenRouter client returns/raises `responses` in order."""
        llm = L.LLM(types.SimpleNamespace(openrouter_key="x", anthropic_key=None))
        self.create = mock.Mock(side_effect=list(responses))
        llm._openrouter = NS(chat=NS(completions=NS(create=self.create)))
        return llm

    def kw(self, i):
        return self.create.call_args_list[i].kwargs

    def call(self, llm, model, max_tokens=4000):
        return llm.call_tool(f"openrouter:{model}", "SYSTEM PROMPT", "USER PROMPT", TOOL, max_tokens=max_tokens)

    def tearDown(self):
        self.prices.assert_not_called()


class ForcesToolTest(unittest.TestCase):
    def test_sonnet_and_opus_not_forced(self):
        self.assertFalse(L.openrouter_forces_tool("anthropic/claude-sonnet-5.5"))
        self.assertFalse(L.openrouter_forces_tool("anthropic/claude-opus-5.5"))

    def test_haiku_and_non_anthropic_forced(self):
        self.assertTrue(L.openrouter_forces_tool("anthropic/claude-haiku-5.5"))
        self.assertTrue(L.openrouter_forces_tool(OTHER))
        self.assertTrue(L.openrouter_forces_tool("google/gemini-3-flash"))


class ForcedToolChoiceTest(OpenRouterBase):
    def test_forced_tool_choice_and_args_dict(self):
        llm = self.make(tool_reply({"verdict": "malicious"}))
        r = self.call(llm, FORCING)
        self.assertEqual(self.create.call_count, 1)
        kw = self.kw(0)
        self.assertEqual(kw["model"], FORCING)
        self.assertEqual(kw["tool_choice"], {"type": "function", "function": {"name": NAME}})
        self.assertEqual(len(kw["tools"]), 1)
        self.assertEqual(kw["tools"][0]["type"], "function")
        self.assertEqual(kw["tools"][0]["function"]["name"], NAME)
        self.assertEqual(kw["tools"][0]["function"]["parameters"], TOOL["input_schema"])
        self.assertIsInstance(r.args, dict)
        self.assertEqual(r.args, {"verdict": "malicious"})
        self.assertEqual(r.provider, "openrouter")
        self.assertEqual(r.usage.cost_usd, 0.001)

    def test_unprefixed_slash_model_goes_to_openrouter(self):
        llm = self.make(tool_reply({"verdict": "benign"}))
        r = llm.call_tool(OTHER, "S", "U", TOOL)
        self.assertEqual(r.provider, "openrouter")
        self.assertEqual(self.kw(0)["model"], OTHER)

    def test_forced_model_without_tool_call_is_not_reprompted(self):
        llm = self.make(text_reply("prose"), tool_reply({"verdict": "x"}))
        r = self.call(llm, FORCING)
        self.assertIsNone(r.args)
        self.assertEqual(r.text, "prose")
        self.assertLessEqual(self.create.call_count, L.OPENROUTER_MAX_CALLS)


class AutoToolChoiceTest(OpenRouterBase):
    def test_auto_tool_choice_for_non_forcing_model(self):
        llm = self.make(tool_reply({"verdict": "benign"}))
        r = self.call(llm, NON_FORCING)
        self.assertEqual(self.kw(0)["tool_choice"], "auto")
        # auto mode must ask for the tool in the prompt itself
        user = self.kw(0)["messages"][-1]
        self.assertEqual(user["role"], "user")
        self.assertIn(NAME, user["content"])
        self.assertEqual(r.args, {"verdict": "benign"})
        self.assertEqual(r.provider, "openrouter")

    def test_single_reprompt_then_args_from_second_reply(self):
        llm = self.make(text_reply("It looks benign to me.", prompt=100, completion=10, cost=0.002),
                        tool_reply({"verdict": "benign"}, prompt=150, completion=30, cost=0.003))
        r = self.call(llm, NON_FORCING)
        self.assertEqual(self.create.call_count, 2)
        first, second = self.kw(0)["messages"], self.kw(1)["messages"]
        self.assertEqual(self.kw(1)["tool_choice"], "auto")
        # history is append-only: second request = first request + assistant turn + user turn
        self.assertEqual(second[:len(first)], first)
        self.assertEqual(len(second), len(first) + 2)
        self.assertEqual(second[-2]["role"], "assistant")
        self.assertEqual(second[-2]["content"], "It looks benign to me.")
        self.assertEqual(second[-1]["role"], "user")
        self.assertIn(NAME, second[-1]["content"])
        self.assertEqual(r.args, {"verdict": "benign"})
        self.assertEqual(r.usage.prompt_tokens, 250)
        self.assertEqual(r.usage.output_tokens, 40)
        self.assertAlmostEqual(r.usage.cost_usd, 0.005)
        self.assertTrue(r.notes, "the re-prompt must be recorded in notes")
        self.assertTrue(any("re-prompt" in n for n in r.notes), r.notes)

    def test_reprompt_after_empty_content_has_non_empty_assistant_turn(self):
        llm = self.make(text_reply(None), tool_reply({"verdict": "benign"}))
        self.call(llm, NON_FORCING)
        assistant = self.kw(1)["messages"][-2]
        self.assertEqual(assistant["role"], "assistant")
        self.assertTrue(assistant["content"], "Anthropic upstreams reject an empty assistant turn")

    def test_never_calls_tool_returns_text_and_bounded_calls(self):
        llm = self.make(*[text_reply("still prose") for _ in range(10)])
        r = self.call(llm, NON_FORCING)
        self.assertIsNone(r.args)
        self.assertEqual(r.text, "still prose")
        self.assertEqual(r.provider, "openrouter")
        self.assertLessEqual(self.create.call_count, 4)
        # exactly one re-prompt: two calls in total
        self.assertEqual(self.create.call_count, 2)

    def test_worst_case_mix_still_bounded(self):
        # rejection + length + prose + prose + ... : never more than OPENROUTER_MAX_CALLS (4) calls.
        responses = [bad_request("tool_choice is not supported"), text_reply("", finish="length")]
        responses += [text_reply("prose") for _ in range(10)]
        llm = self.make(*responses)
        r = self.call(llm, FORCING)
        self.assertIsNone(r.args)
        self.assertLessEqual(self.create.call_count, 4)


class BadRequestFallbackTest(OpenRouterBase):
    def test_forced_rejected_retries_auto(self):
        llm = self.make(bad_request("Error code: 400 - tool_choice forcing is not supported for this model"),
                        tool_reply({"verdict": "malicious"}))
        r = self.call(llm, FORCING)
        self.assertEqual(self.create.call_count, 2)
        self.assertEqual(self.kw(0)["tool_choice"], {"type": "function", "function": {"name": NAME}})
        self.assertEqual(self.kw(1)["tool_choice"], "auto")
        self.assertIn(NAME, self.kw(1)["messages"][-1]["content"])
        self.assertEqual(r.args, {"verdict": "malicious"})
        self.assertTrue(r.notes)

    def test_tool_choice_only_in_body_also_falls_back(self):
        body = {"error": {"message": "Provider returned error", "metadata": {"raw": "tool_choice: forced not allowed"}}}
        llm = self.make(bad_request("Provider returned error", body=body), tool_reply({"verdict": "x"}))
        r = self.call(llm, FORCING)
        self.assertEqual(self.kw(1)["tool_choice"], "auto")
        self.assertEqual(r.args, {"verdict": "x"})

    def test_other_bad_request_raises_runtime_error(self):
        llm = self.make(bad_request("context length exceeded"), tool_reply({"verdict": "x"}))
        with self.assertRaises(RuntimeError):
            self.call(llm, FORCING)
        self.assertEqual(self.create.call_count, 1)

    def test_tool_choice_error_in_auto_mode_raises(self):
        # Already in auto mode: nothing to fall back to.
        llm = self.make(bad_request("tool_choice auto is not supported"), tool_reply({"verdict": "x"}))
        with self.assertRaises(RuntimeError):
            self.call(llm, NON_FORCING)
        self.assertEqual(self.create.call_count, 1)


class LengthRetryTest(OpenRouterBase):
    def test_length_retries_with_larger_max_tokens(self):
        llm = self.make(text_reply("", finish="length", cost=0.001),
                        tool_reply({"verdict": "benign"}, cost=0.002))
        r = self.call(llm, FORCING, max_tokens=1000)
        self.assertEqual(self.create.call_count, 2)
        self.assertEqual(self.kw(0)["max_tokens"], 1000)
        self.assertGreater(self.kw(1)["max_tokens"], 1000)
        self.assertEqual(r.args, {"verdict": "benign"})
        self.assertAlmostEqual(r.usage.cost_usd, 0.003)

    def test_truncated_tool_call_is_not_parsed(self):
        # finish_reason=length with a (truncated) tool call: must retry, not json-parse garbage.
        msg = NS(role="assistant", content=None,
                 tool_calls=[NS(function=NS(name=NAME, arguments='{"verdict": "mal'))])
        truncated = NS(choices=[NS(finish_reason="length", message=msg)], usage=usage())
        llm = self.make(truncated, tool_reply({"verdict": "malicious"}))
        r = self.call(llm, FORCING, max_tokens=500)
        self.assertEqual(r.args, {"verdict": "malicious"})
        self.assertGreater(self.kw(1)["max_tokens"], 500)

    def test_repeated_length_gives_up_bounded(self):
        llm = self.make(*[text_reply("", finish="length") for _ in range(10)])
        r = self.call(llm, FORCING)
        self.assertIsNone(r.args)
        self.assertEqual(r.stop_reason, "length")
        self.assertLessEqual(self.create.call_count, 4)


class CachingTest(OpenRouterBase):
    def test_anthropic_id_system_has_cache_control(self):
        for model in (FORCING, NON_FORCING):
            with self.subTest(model=model):
                llm = self.make(tool_reply({"verdict": "x"}))
                self.call(llm, model)
                system = self.kw(0)["messages"][0]
                self.assertEqual(system["role"], "system")
                self.assertIsInstance(system["content"], list)
                self.assertEqual(len(system["content"]), 1)
                part = system["content"][0]
                self.assertEqual(part["type"], "text")
                self.assertEqual(part["text"], "SYSTEM PROMPT")
                self.assertEqual(part["cache_control"], {"type": "ephemeral"})

    def test_non_anthropic_id_system_is_plain_string(self):
        llm = self.make(tool_reply({"verdict": "x"}))
        self.call(llm, OTHER)
        system = self.kw(0)["messages"][0]
        self.assertEqual(system, {"role": "system", "content": "SYSTEM PROMPT"})

    def test_cache_control_kept_on_reprompt(self):
        llm = self.make(text_reply("prose"), tool_reply({"verdict": "x"}))
        self.call(llm, NON_FORCING)
        self.assertEqual(self.kw(1)["messages"][0]["content"][0]["cache_control"], {"type": "ephemeral"})


class UsageTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch("socagent.llm._openrouter_prices",
                       side_effect=AssertionError("_openrouter_prices must not be called (network)"))
        self.prices = p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.prices.assert_not_called()

    def test_cached_and_written_tokens(self):
        u = L.LLM._openrouter_usage(FORCING, usage(prompt=5000, completion=300, cached=4000, written=600,
                                                   cost=0.0123), 1.5)
        self.assertEqual(u.cache_read_tokens, 4000)
        self.assertEqual(u.cache_write_tokens, 600)
        self.assertEqual(u.input_tokens, 400)
        self.assertEqual(u.prompt_tokens, 5000)
        self.assertEqual(u.output_tokens, 300)
        self.assertEqual(u.cost_usd, 0.0123)
        self.assertEqual(u.latency_s, 1.5)
        self.assertEqual(u.model, f"openrouter:{FORCING}")

    def test_no_cache_write_field(self):
        u = L.LLM._openrouter_usage(OTHER, usage(prompt=1000, completion=50, cached=200, cost=0.0004), 0.1)
        self.assertEqual(u.cache_read_tokens, 200)
        self.assertEqual(u.cache_write_tokens, 0)
        self.assertEqual(u.prompt_tokens, 1000)
        self.assertEqual(u.cost_usd, 0.0004)

    def test_no_prompt_tokens_details(self):
        raw = NS(prompt_tokens=800, completion_tokens=10, prompt_tokens_details=None, cost=0.0002)
        u = L.LLM._openrouter_usage(OTHER, raw, 0.0)
        self.assertEqual(u.cache_read_tokens, 0)
        self.assertEqual(u.cache_write_tokens, 0)
        self.assertEqual(u.prompt_tokens, 800)
        self.assertEqual(u.cost_usd, 0.0002)

    def test_zero_reported_cost_is_used(self):
        # A reported cost of 0 (free model) is still a reported cost: no price-list fallback.
        u = L.LLM._openrouter_usage(OTHER, usage(cost=0), 0.0)
        self.assertEqual(u.cost_usd, 0.0)

    def test_missing_usage_is_zero(self):
        u = L.LLM._openrouter_usage(OTHER, None, 0.2)
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.cost_usd), (0, 0, 0.0))


if __name__ == "__main__":
    unittest.main()
