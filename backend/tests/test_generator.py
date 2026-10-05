import io
import statistics
from datetime import UTC

import pytest

from app.generator import Generator, GeneratorConfig
from app.parsing.csv_parser import CsvParser

SMALL = GeneratorConfig(days=7, users=10, seed=7)  # small but has every planted attack


def generate(config: GeneratorConfig) -> tuple[str, list]:
    out = io.StringIO()
    plants = Generator(config).write(out)
    return out.getvalue(), plants


def parse_all(text: str) -> tuple[dict[int, object], CsvParser]:
    parser = CsvParser(UTC)
    events = {e.line_no: e for e in parser.parse(text.splitlines(keepends=True))}
    return events, parser


def test_same_seed_gives_identical_output():
    assert generate(SMALL)[0] == generate(SMALL)[0]
    assert generate(SMALL)[0] != generate(GeneratorConfig(days=7, users=10, seed=8))[0]


@pytest.mark.parametrize("variant", [{}, {"header": True}, {"time_format": "nss"}])
def test_every_generated_line_parses_with_our_parser(variant):
    config = GeneratorConfig(days=7, users=10, seed=7, **variant)
    text, _ = generate(config)

    events, parser = parse_all(text)

    assert parser.stats.bad_lines == 0
    assert parser.stats.good_lines == len(events) > 1000


def test_all_nine_attack_kinds_are_planted():
    _, plants = generate(SMALL)

    assert {p.kind for p in plants} == {
        "executable_download", "beaconing", "zscaler_threat", "high_risk_allowed",
        "request_burst", "rare_domain", "off_hours", "large_upload",
        "lookalike_domain",  # For the AI domain classifier
    }
    assert all(p.line_nos for p in plants)


def test_the_ai_plants_leave_every_older_row_unchanged(monkeypatch):
    """The AI plants use their own random stream and are added last, so a week generated
    without them is exactly the same week minus the new lines."""
    with_ai, _ = generate(SMALL)
    monkeypatch.setattr(Generator, "_ai_plants_for_day", lambda self, day_index, day: [])
    without, _ = generate(SMALL)

    new_lines = [line for line in with_ai.splitlines() if "rnicrosoft-login.com" in line or "msftconnecttest" in line]
    assert new_lines and [line for line in with_ai.splitlines() if line not in new_lines] == without.splitlines()


def test_answer_key_lines_really_contain_each_attack():
    text, plants = generate(SMALL)
    events, _ = parse_all(text)
    lines = {p.kind: [events[n] for n in p.line_nos] for p in plants}

    exe = lines["executable_download"][0]
    assert exe.file_type == "exe" and exe.user_agent.startswith("python-requests")

    threats = lines["zscaler_threat"]
    assert all(e.action == "Blocked" and e.threat and e.risk_score >= 90 for e in threats)

    assert all(e.action == "Allowed" and e.risk_score >= 80 for e in lines["high_risk_allowed"])

    uploads = lines["large_upload"]
    assert all(e.method == "POST" and e.host == "mega.nz" for e in uploads)
    assert sum(e.bytes_out for e in uploads) >= 390_000_000

    beacon = lines["beaconing"]
    gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(beacon, beacon[1:])]
    assert {e.host for e in beacon} == {"cdn-update-check.xyz"}
    assert 58 <= statistics.mean(gaps) <= 62 and statistics.pstdev(gaps) < 2  # machine-regular

    burst = lines["request_burst"]
    assert len(burst) == 600 and (burst[-1].ts - burst[0].ts).total_seconds() <= 120

    off = lines["off_hours"]
    assert all(e.ts.weekday() == 6 and e.ts.hour < 4 for e in off)  # Sunday, before 4 am

    rare_hosts = [e.host for e in lines["rare_domain"]]
    all_hosts = [e.host for e in events.values()]
    assert all(all_hosts.count(h) == 1 for h in rare_hosts)  # each seen exactly once


def test_clean_mode_plants_nothing():
    text, plants = generate(GeneratorConfig(days=7, users=10, seed=7, clean=True))
    events, _ = parse_all(text)

    assert plants == []
    # Look-alikes are allowed (that's the point), but nothing malicious: no threats, executables
    # only from Microsoft updates, big uploads only to company storage.
    assert not any(e.threat for e in events.values())
    assert all(e.host == "update.microsoft.com" for e in events.values() if e.file_type in ("exe", "msi"))
    assert all(e.host in ("drive.google.com", "acme.sharepoint.com")
               for e in events.values() if e.bytes_out > 10_000_000)


def test_attacks_need_a_full_week():
    with pytest.raises(ValueError, match="7 days"):
        Generator(GeneratorConfig(days=3))


def test_target_size_adds_whole_days_and_stops():
    week, _ = generate(SMALL)
    target_mb = len(week) * 1.5 / 1_000_000  # ask for ~1.5 weeks of data

    text, _ = generate(GeneratorConfig(days=7, users=10, seed=7, target_mb=target_mb))

    assert len(text) >= target_mb * 1_000_000 * 0.9
    assert len(text) < len(week) * 3  # stopped, didn't run away


# ---- innocent look-alikes (hard negatives) ----

BENIGN_KINDS = {"legit_update_download", "dev_scripted_client", "legit_large_upload",
                "mid_risk_allowed", "app_polling", "evening_worker", "real_brand_domain"}


@pytest.mark.parametrize("clean", [False, True])
def test_benign_lookalikes_exist_in_both_modes(clean):
    generator = Generator(GeneratorConfig(days=7, users=10, seed=7, clean=clean))
    generator.write(io.StringIO())

    assert set(generator.benign) == BENIGN_KINDS


def test_benign_lookalikes_resemble_the_attacks_they_imitate():
    generator = Generator(SMALL)
    out = io.StringIO()
    generator.write(out)
    events, _ = parse_all(out.getvalue())
    lines = {k: [events[n] for n in p.line_nos] for k, p in generator.benign.items()}

    assert all(e.file_type in ("exe", "msi") and e.action == "Allowed" for e in lines["legit_update_download"])
    assert all(e.user_agent.startswith("curl/") for e in lines["dev_scripted_client"])
    assert all(e.method == "POST" and e.bytes_out >= 50_000_000 for e in lines["legit_large_upload"])
    assert all(40 <= e.risk_score <= 60 and e.action == "Allowed" for e in lines["mid_risk_allowed"])

    polling = lines["app_polling"]
    by_user: dict[str, list] = {}
    for e in polling:
        by_user.setdefault(e.username, []).append(e)
    first_run = sorted(next(iter(by_user.values())), key=lambda e: e.ts)[:60]
    gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(first_run, first_run[1:])]
    assert statistics.pstdev(gaps) < 5  # regular, like beaconing

    evening = generator.benign["evening_worker"].username.split(",")
    late = [e for e in events.values() if e.username in evening and e.ts.hour >= 19]
    assert late  # they really do work evenings, routinely


@pytest.mark.parametrize(
    ("host", "category"),
    [("novahealth.co", "Health"), ("travelglobal.io", "Travel"), ("datagreen.com", "Information Technology"),
     ("marketprime.net", "Finance"), ("healthtravel.com", "Health"),  # first meaningful word wins
     ("novaapex.com", "Business and Economy")],
)
def test_generic_domain_category_matches_its_name(host, category):
    from app.generator import category_for_host

    assert category_for_host(host) == category


def test_devices_follow_each_user_and_some_users_have_none():
    events, _ = parse_all(generate(GeneratorConfig(days=7, users=40, seed=7))[0])

    devices: dict[str, set] = {}
    for e in events.values():
        devices.setdefault(e.username, set()).add((e.device, e.device_os))
    without = [u for u, d in devices.items() if d == {(None, None)}]
    two = [u for u, d in devices.items() if len(d) == 2]

    assert 0 < len(without) < len(devices) / 2  # some users without Client Connector, not most
    assert two  # some users have a second laptop
    for user, seen in devices.items():
        for device, os_type in seen:
            assert device is None or (device.startswith(f"LT-{user.upper()}-") and os_type in ("Windows", "macOS"))
