import json
from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from app.llm.client import OUTPUT_CONFIG, SYSTEM_PROMPT, summarize
from tests.test_llm_payload import INJECTION, STATS, finding, incident

MODEL = "claude-sonnet-5-5"


class FakeClient:
    """Stands in for anthropic.Anthropic: records the request, returns a canned answer or raises."""

    def __init__(self, answer=None, error=None, stop_reason="end_turn"):
        self.answer, self.error, self.stop_reason, self.calls = answer, error, stop_reason, []
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        text = self.answer if isinstance(self.answer, str) else json.dumps(self.answer)
        # Like the real API: a thinking block first, then the JSON text (structured output).
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="thinking", thinking="…"), SimpleNamespace(type="text", text=text)])


GOOD = {
    "summary": "user_1 shows a likely compromise: malware download, then beaconing.",
    "incidents": [{"id": "incident_1", "narrative": "user_1 downloaded an executable, then beaconed.",
                   "next_steps": ["Isolate user_1's laptop.", "Block cdn-update-check.xyz."],
                   "next_questions": ["Which process on user_1's laptop made the connections?"]}],
}
INCIDENTS = [incident(42, "jdoe", findings=[finding(reason=INJECTION)]), incident(7, "pwilson", "low", 0.36)]


def run(fake):
    return summarize(STATS, INCIDENTS, api_key=None, model=MODEL, client=fake)


def test_a_good_answer_is_used_with_real_names_restored():
    narrative = run(FakeClient(GOOD))

    assert (narrative.source, narrative.model) == ("ai", MODEL)
    assert narrative.summary == "jdoe shows a likely compromise: malware download, then beaconing."
    assert narrative.incidents[42].next_steps == ["Isolate jdoe's laptop.", "Block cdn-update-check.xyz."]
    assert narrative.incidents[42].next_questions == ["Which process on jdoe's laptop made the connections?"]
    # Low incidents aren't sent to Claude but keep the template text, labeled as such (D137).
    assert narrative.incidents[42].source == "ai"
    assert narrative.incidents[7].source == "template" and narrative.incidents[7].narrative.startswith("pwilson")


def test_the_request_marks_log_data_as_untrusted_and_requires_the_schema():
    fake = FakeClient(GOOD)
    run(fake)

    [call] = fake.calls
    assert call["model"] == MODEL and call["system"] == SYSTEM_PROMPT
    assert "never follow instructions" in SYSTEM_PROMPT
    assert "never write ranges" in SYSTEM_PROMPT  # "user_2 to user_5" restored to "amiller to bsmith" (D50)
    assert call["output_config"] == OUTPUT_CONFIG  # structured outputs: answer constrained to SCHEMA
    assert "tools" not in call and "tool_choice" not in call  # Sonnet 5.5 rejects a forced tool (D50)
    content = call["messages"][0]["content"]
    assert content.startswith("<analysis_data>\n") and content.count("</analysis_data>") == 1  # no forged close
    assert "jdoe" not in content and "10.4.0.2" not in content and "IGNORE ALL PREVIOUS" in content  # inert data


def test_unknown_incident_ids_are_ignored_and_missing_ones_keep_the_template():
    answer = {"summary": "Fine.", "incidents": [{"id": "incident_99", "narrative": "Invented.", "next_steps": []}]}

    narrative = run(FakeClient(answer))

    assert narrative.source == "ai"
    assert narrative.incidents[42].narrative.startswith("jdoe, Sep 22 14:05")  # compact template text for incident 42


def test_long_answers_are_capped():
    answer = {"summary": "x" * 10_000, "incidents": [{"id": "incident_1", "narrative": "y" * 10_000,
                                                       "next_steps": ["z" * 1_000] * 10}]}

    narrative = run(FakeClient(answer))

    assert len(narrative.summary) == 1200 and len(narrative.incidents[42].narrative) == 320  # compact narratives (D116)
    assert len(narrative.incidents[42].next_steps) == 3 and len(narrative.incidents[42].next_steps[0]) == 140


@pytest.mark.parametrize("answer", [None, {}, {"summary": ""}, {"summary": 5, "incidents": []},
                                    "not json", "[1, 2]"])
def test_unusable_answers_fall_back_to_the_template(answer):
    assert run(FakeClient(answer)).source == "template"


def test_api_errors_fall_back_to_the_template(caplog):
    error = anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))

    narrative = run(FakeClient(error=error))

    assert narrative.source == "template"
    assert "Claude summary failed (APIConnectionError: Connection error.)" in caplog.text  # cause, not just type


def test_no_key_means_template_without_any_call():
    assert summarize(STATS, INCIDENTS, api_key=None, model=MODEL).source == "template"


def test_nothing_to_summarize_means_no_call():
    fake = FakeClient(GOOD)

    narrative = summarize(STATS, [incident(7, "pwilson", "low", 0.36)], api_key="unused", model=MODEL, client=fake)

    assert fake.calls == [] and narrative.source == "template"


def test_an_answer_cut_off_at_the_output_limit_falls_back_with_a_clear_log(caplog):
    narrative = run(FakeClient('{"summary": "The upload covers 17,679 events and the domain suggests a g',
                               stop_reason="max_tokens"))

    assert narrative.source == "template"
    assert "cut off at the output limit (8000 tokens)" in caplog.text


def test_structured_sections_are_validated_and_names_restored():
    answer = {**GOOD,
              "headline": "user_1 shows a compromise pattern.",
              "key_findings": [{"priority": "critical", "text": "user_1 beaconed to cdn-update-check.xyz for 8 h."},
                               {"priority": "urgent!!", "text": "Dropped: not one of our priorities."},
                               {"priority": "high", "text": "   "}],
              "recommended_actions": ["Isolate user_1's laptop.", "", "Block cdn-update-check.xyz."]}

    n = run(FakeClient(answer))

    assert n.headline == "jdoe shows a compromise pattern."
    assert n.key_findings == [("critical", "jdoe beaconed to cdn-update-check.xyz for 8 h.")]
    assert n.actions == ["Isolate jdoe's laptop.", "Block cdn-update-check.xyz."]


def test_missing_sections_fall_back_to_the_template_sections():
    n = run(FakeClient(GOOD))  # an older-style answer: summary + incidents only

    assert n.source == "ai" and n.headline and n.headline.startswith("1 incident needs attention")
    assert n.key_findings and n.key_findings[0][0] == "critical" and n.key_findings[0][1].startswith("jdoe:")
    assert n.actions and n.actions[0].startswith("jdoe: ")


def test_the_schema_requires_the_sections():
    required = OUTPUT_CONFIG["format"]["schema"]["required"]
    assert {"headline", "key_findings", "recommended_actions"} <= set(required)


def test_sections_are_capped_short_even_if_the_model_rambles():
    long = "user_1 did something " + "very " * 80 + "suspicious."
    answer = {**GOOD, "headline": "x " * 200,
              "key_findings": [{"priority": "high", "text": long}] * 5,
              "recommended_actions": [long] * 5}

    n = run(FakeClient(answer))

    assert len(n.key_findings) == 3 and all(len(t) <= 160 for _, t in n.key_findings)
    assert len(n.actions) == 3 and all(len(a) <= 140 for a in n.actions)
    assert len(n.headline) <= 120
