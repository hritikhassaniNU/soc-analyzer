"""Detection quality gate: 5 generated weeks with attacks + 5 without, through the real detection.
If a threshold change makes us miss a planted attack, raise a look-alike, or alarm on a clean week,
this fails. (~6 s; runs in every pytest on purpose.)"""

from app.evaluate import DEFAULT_SEEDS, evaluate, markdown

ATTACK_KINDS = {"executable_download", "beaconing", "zscaler_threat", "high_risk_allowed",
                "request_burst", "rare_domain", "off_hours", "large_upload"}


def test_detection_quality_on_five_generated_weeks():
    result = evaluate(DEFAULT_SEEDS)

    assert set(result.attacks) == ATTACK_KINDS
    assert all(len(by_seed) == len(DEFAULT_SEEDS) for by_seed in result.attacks.values())
    assert result.missed_attacks() == []       # every attack inside a medium+ incident
    assert result.raised_lookalikes() == []    # no look-alike reaches medium+
    assert result.clean_false_alarms() == 0    # attack-free weeks: low only
    report = markdown(result)
    assert "Missed attacks: 0 · look-alikes at medium+: 0 · clean-week medium+ incidents: 0" in report
