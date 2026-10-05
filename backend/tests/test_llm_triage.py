"""D135: the AI's triage suggestion and next-step searches picked from our menu."""

from dataclasses import replace
from datetime import timedelta

from app.llm.client import TRIAGE_OUTPUT_CONFIG, TRIAGE_RULES, summarize
from app.llm.payload import build_payload
from app.llm.searches import search_menu
from app.llm.template import template_narrative
from tests.test_llm_client import MODEL, FakeClient
from tests.test_llm_payload import STATS, T, finding, incident

BEACON = replace(finding(reason="480 requests to cdn-update-check.xyz"), details={"host": "cdn-update-check.xyz"})
INCIDENTS = [incident(42, "jdoe", findings=[BEACON])]


def answer(**incident_fields):
    return {"headline": "h", "key_findings": [], "recommended_actions": [], "summary": "user_1 beaconed.",
            "incidents": [{"id": "incident_1", "narrative": "user_1 beaconed.", "next_steps": [], "next_questions": [],
                           **incident_fields}]}


def run(fake):
    return summarize(STATS, INCIDENTS, api_key=None, model=MODEL, client=fake, triage=True)


def test_the_menu_offers_flagged_events_each_host_its_blast_radius_and_context():
    menu = search_menu("jdoe", T, T + timedelta(hours=8, seconds=30), [{"host": "cdn-update-check.xyz"}])

    assert [s.id for s in menu] == ["flagged", "host1", "everyone_host1", "blocked", "before", "all"]
    flagged = menu[0]
    assert (flagged.username, flagged.anomalous, flagged.start) == ("jdoe", True, T)
    assert flagged.end == T + timedelta(hours=8, minutes=1)  # rounded out: the last event is inside
    assert (menu[2].username, menu[2].host, menu[2].start) == (None, "cdn-update-check.xyz", None)


def test_the_payload_sends_the_menu_with_stand_in_names_only_when_triage_is_asked():
    plain, _ = build_payload(STATS, INCIDENTS)
    payload, stand_ins = build_payload(STATS, INCIDENTS, triage=True)

    assert "searches" not in plain["incidents"][0]
    whats = [s["what"] for s in payload["incidents"][0]["searches"]]
    assert "user_1 → cdn-update-check.xyz in the window" in whats
    assert not any("jdoe" in w for w in whats)
    assert set(stand_ins.searches["incident_1"]) >= {"flagged", "host1"}


def test_the_model_picks_by_id_and_only_labels_its_choices():
    narrative = run(FakeClient(answer(
        assessment={"verdict": "likely_malicious", "confidence": "high", "reason": "user_1's beacon follows an exe."},
        searches=[{"id": "host1", "label": "user_1's beacon traffic"},
                  {"id": "made_up", "label": "Everything"},             # not offered: ignored
                  {"id": "host1", "label": "again"},                    # duplicate: ignored
                  {"id": "everyone_host1", "label": "Who else hit it"}])))

    jdoe = narrative.incidents[42]
    assert jdoe.assessment == {"verdict": "likely_malicious", "confidence": "high",
                               "reason": "jdoe's beacon follows an exe."}
    assert [(s["id"], s["label"]) for s in jdoe.searches] == [("host1", "jdoe's beacon traffic"),
                                                            ("everyone_host1", "Who else hit it")]
    assert jdoe.searches[0]["host"] == "cdn-update-check.xyz" and jdoe.searches[0]["username"] == "jdoe"


def test_the_request_asks_for_triage_with_its_schema():
    fake = FakeClient(answer(assessment={"verdict": "likely_benign", "confidence": "low", "reason": "r"}, searches=[]))
    run(fake)

    [call] = fake.calls
    assert call["system"].endswith(TRIAGE_RULES) and call["output_config"] == TRIAGE_OUTPUT_CONFIG
    assert "never a percentage" in TRIAGE_RULES


def test_invalid_triage_is_dropped_and_searches_fall_back_to_the_defaults():
    narrative = run(FakeClient(answer(assessment={"verdict": "pwned", "confidence": "high", "reason": "x"},
                                      searches=[{"id": "nope", "label": "x"}])))

    jdoe = narrative.incidents[42]
    assert jdoe.assessment is None
    assert [s["id"] for s in jdoe.searches] == ["flagged", "host1", "everyone_host1"]


def test_the_template_gives_default_searches_and_no_verdict():
    jdoe = template_narrative(INCIDENTS).incidents[42]

    assert jdoe.assessment is None
    assert [s["id"] for s in jdoe.searches] == ["flagged", "host1", "everyone_host1"]
    assert jdoe.searches[0]["start"] == T.isoformat()  # JSON-ready for the narrative document
