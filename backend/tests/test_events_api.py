import io
from datetime import datetime, timedelta

import pytest

from app.generator import Generator, GeneratorConfig
from app.pipeline.analyze import analyze

pytestmark = pytest.mark.integration

GOOD = ("analyst", "correct-horse-1")


@pytest.fixture(scope="module")
def generated():
    out = io.StringIO()
    generator = Generator(GeneratorConfig(days=7, users=6, seed=21))
    generator.write(out)
    return out.getvalue().encode(), generator


@pytest.fixture
def upload_id(client, analyst, generated, storage):
    client.post("/api/login", auth=GOOD)
    content, _ = generated
    uid = client.post("/api/uploads", files={"file": ("proxy.log", content, "text/plain")}).json()["id"]
    analyze(uid, storage)
    return uid


def fetch_all(client, upload_id, **params) -> list[dict]:
    """Follow next_cursor until the last page."""
    items, cursor = [], None
    while True:
        query = {**params, **({"cursor": cursor} if cursor else {})}
        page = client.get(f"/api/uploads/{upload_id}/events", params=query).json()
        items += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return items


def test_first_page_is_time_ordered_with_a_cursor(client, upload_id):
    page = client.get(f"/api/uploads/{upload_id}/events", params={"limit": 50}).json()

    assert len(page["items"]) == 50 and page["next_cursor"]
    keys = [(e["ts"], e["line_no"]) for e in page["items"]]
    assert keys == sorted(keys)


def test_paging_covers_every_row_exactly_once(client, upload_id, generated):
    content, _ = generated
    total_lines = len(content.decode().splitlines())

    items = fetch_all(client, upload_id, limit=200)

    line_numbers = [e["line_no"] for e in items]
    assert len(line_numbers) == total_lines
    assert len(set(line_numbers)) == total_lines  # no duplicates, no gaps
    # The burst (600 requests in 2 minutes) has many events sharing a timestamp:
    # line_no as tie-breaker is what keeps the page boundaries exact.


def test_filters_combine(client, upload_id):
    blocked = fetch_all(client, upload_id, action="Blocked", limit=200)
    jdoe = fetch_all(client, upload_id, username="JDOE", limit=200)  # case-insensitive
    jdoe_blocked = fetch_all(client, upload_id, username="jdoe", action="Blocked", limit=200)

    assert blocked and all(e["action"] == "Blocked" for e in blocked)
    assert jdoe and all(e["username"] == "jdoe" for e in jdoe)
    assert {e["line_no"] for e in jdoe_blocked} == {e["line_no"] for e in jdoe} & {e["line_no"] for e in blocked}


def test_flagged_and_rule_filters_find_the_planted_attacks(client, upload_id, generated):
    _, generator = generated
    plants = {p.kind: set(p.line_nos) for p in generator.plants}

    threats = fetch_all(client, upload_id, rule="zscaler_threat")
    flagged = {e["line_no"] for e in fetch_all(client, upload_id, flagged=True, limit=200)}

    assert {e["line_no"] for e in threats} == plants["zscaler_threat"]
    assert plants["executable_download"] <= flagged
    assert all(e["rule_hits"] for e in fetch_all(client, upload_id, flagged=True, limit=200))


def test_time_window(client, upload_id, generated):
    _, generator = generated
    burst = next(p for p in generator.plants if p.kind == "request_burst")
    start = datetime.fromisoformat(burst.start)

    window = fetch_all(client, upload_id, username="bsmith", start=start.isoformat(),
                       end=(start + timedelta(minutes=2)).isoformat(), limit=200)

    returned = {e["line_no"] for e in window}
    assert set(burst.line_nos) <= returned  # all 600 burst lines...
    assert all(e["username"] == "bsmith" for e in window)
    assert all(start <= datetime.fromisoformat(e["ts"]) < start + timedelta(minutes=2) for e in window)
    # ...plus anything else bsmith did in those 2 minutes (here: one ad-pixel request).
    # A drill-down window must show everything, not just the planted lines.


@pytest.mark.parametrize(
    ("params", "status"),
    [({"cursor": "not-a-cursor!!"}, 400), ({"action": "Maybe"}, 422), ({"rule": "made_up"}, 422),
     ({"limit": 0}, 422), ({"limit": 500}, 422)],
)
def test_bad_parameters(client, upload_id, params, status):
    assert client.get(f"/api/uploads/{upload_id}/events", params=params).status_code == status


def test_unknown_upload_is_404(client, upload_id):
    assert client.get("/api/uploads/99999/events").status_code == 404


def test_events_inside_finding_windows_are_marked(client, upload_id, generated):
    _, generator = generated
    beacon = next(p for p in generator.plants if p.kind == "beaconing")

    inside = fetch_all(client, upload_id, in_window=True, username="jdoe", limit=200)

    beacon_lines = set(beacon.line_nos)
    assert beacon_lines <= {e["line_no"] for e in inside}  # every beacon request is inside a window
    assert all(e["windows"] for e in inside)
    # Host-scoped: "beaconing" marks ONLY requests to the beacon's host, not other browsing
    # in the same 8 hours.
    beaconing = [e for e in inside if "beaconing" in e["windows"]]
    assert {e["line_no"] for e in beaconing} == beacon_lines
    assert {e["host"] for e in beaconing} == {"cdn-update-check.xyz"}
    # Window marks exist only on events inside a window (the default list shows both kinds).
    everything = fetch_all(client, upload_id, username="jdoe", limit=200)
    assert {e["line_no"] for e in everything if e["windows"]} == {e["line_no"] for e in inside}


def test_window_and_rule_filters_combine(client, upload_id):
    # Rule findings are line-level: they never become windows themselves. amiller's threat hour
    # may still sit inside an ML "unusual combination" window (an hour-level finding).
    threat_only = fetch_all(client, upload_id, rule="zscaler_threat")
    both = fetch_all(client, upload_id, rule="zscaler_threat", in_window=True)

    assert threat_only
    assert all(set(e["windows"]) <= {"behavioral_outlier"} for e in threat_only)
    assert {e["line_no"] for e in both} == {e["line_no"] for e in threat_only if e["windows"]}


def test_rare_domain_windows_cover_only_those_domains(client, upload_id, generated):
    _, generator = generated
    plant = next(p for p in generator.plants if p.kind == "rare_domain")

    marked = [e for e in fetch_all(client, upload_id, username=plant.username, in_window=True, limit=200)
              if "rare_domain" in e["windows"]]

    assert {e["line_no"] for e in marked} == set(plant.line_nos)


def test_search_box_matches_user_ip_host_category_and_device(client, upload_id):
    everything = fetch_all(client, upload_id, limit=200)
    jdoe = next(e for e in everything if e["username"] == "jdoe")

    by_user = fetch_all(client, upload_id, q="JDO", limit=200)  # contains, case-insensitive
    by_ip = fetch_all(client, upload_id, q=jdoe["client_ip"], limit=200)
    by_host = fetch_all(client, upload_id, q="anonshare", limit=200)
    by_category = fetch_all(client, upload_id, q="file shar", limit=200)

    assert by_user and all("jdo" in e["username"] for e in by_user)
    assert by_ip and all(jdoe["client_ip"] in e["client_ip"] for e in by_ip)
    assert by_host and all("anonshare" in (e["host"] or "") for e in by_host)
    assert by_category and all("file shar" in (e["category"] or "").lower() for e in by_category)
    device = next(e["device"] for e in everything if e["device"])  # most generated users have a laptop
    by_device = fetch_all(client, upload_id, q=device.lower(), limit=200)
    assert by_device and all(e["device"] == device for e in by_device)


def test_search_treats_like_wildcards_as_text(client, upload_id):
    # No searched field contains a literal % or _ in this data, so escaped wildcards match nothing
    # (unescaped, "%" and "_" would match every row).
    assert fetch_all(client, upload_id, q="%", limit=200) == []
    assert fetch_all(client, upload_id, q="_", limit=200) == []


def test_severity_source_and_anomaly_only(client, upload_id):
    flagged = fetch_all(client, upload_id, flagged=True, limit=200)
    high = fetch_all(client, upload_id, min_score=0.75, limit=200)
    stat = fetch_all(client, upload_id, window_source="stat", limit=200)
    windows = fetch_all(client, upload_id, in_window=True, limit=200)
    anomalous = fetch_all(client, upload_id, anomalous=True, limit=200)

    assert high and all(e["rule_max_score"] >= 0.75 for e in high) and len(high) < len(flagged)
    assert stat and {e["line_no"] for e in stat} <= {e["line_no"] for e in windows}
    # Anomaly only = matched a rule OR inside a finding window (exactly the union).
    assert {e["line_no"] for e in anomalous} == {e["line_no"] for e in flagged} | {e["line_no"] for e in windows}
    assert client.get(f"/api/uploads/{upload_id}/events", params={"min_score": 2}).status_code == 422
    assert client.get(f"/api/uploads/{upload_id}/events", params={"window_source": "rule"}).status_code == 422


def test_count_matches_the_rows_for_any_filter(client, upload_id):
    for params in ({}, {"q": "jdoe"}, {"anomalous": True}, {"action": "Blocked", "min_score": 0.45}):
        total = client.get(f"/api/uploads/{upload_id}/events/count", params=params).json()["total"]
        assert total == len(fetch_all(client, upload_id, limit=200, **params))
    assert client.get("/api/uploads/999999/events/count").status_code == 404


def test_jumping_with_an_offset_gives_the_same_page_as_walking_with_cursors(client, upload_id):
    walked, cursor = [], None
    for _ in range(3):  # walk to page 3 with keyset cursors (25 per page)
        page = client.get(f"/api/uploads/{upload_id}/events",
                          params={"limit": 25, **({"cursor": cursor} if cursor else {})}).json()
        walked.append(page)
        cursor = page["next_cursor"]

    jumped = client.get(f"/api/uploads/{upload_id}/events", params={"limit": 25, "offset": 50}).json()

    assert [e["line_no"] for e in jumped["items"]] == [e["line_no"] for e in walked[2]["items"]]
    assert jumped["next_cursor"] == walked[2]["next_cursor"]  # Next from a jumped page continues by keyset
    assert client.get(f"/api/uploads/{upload_id}/events", params={"offset": -1}).status_code == 422


def test_severity_checkboxes_are_bands_and_counts_cover_each(client, upload_id):
    everything = fetch_all(client, upload_id, limit=200)
    def band(score):
        return ("critical" if score >= 0.95 else "high" if score >= 0.75 else "medium" if score >= 0.45
                else "low" if score > 0 else "none")

    counts = client.get(f"/api/uploads/{upload_id}/events/count", params={"severity": ["high"]}).json()
    critical_high = fetch_all(client, upload_id, severity=["critical", "high"], limit=200)

    expected = {b: sum(band(e["rule_max_score"]) == b for e in everything) for b in ("critical", "high", "medium", "low", "none")}
    assert counts["by_severity"] == expected  # counts ignore the severity filter itself
    assert counts["total"] == expected["high"]
    assert {band(e["rule_max_score"]) for e in critical_high} <= {"critical", "high"}
    assert len(critical_high) == expected["critical"] + expected["high"]
    assert client.get(f"/api/uploads/{upload_id}/events", params={"severity": "extreme"}).status_code == 422


def test_source_checkboxes_are_or_ed(client, upload_id):
    exe = fetch_all(client, upload_id, rule="executable_download", limit=200)
    stat = fetch_all(client, upload_id, window_source="stat", limit=200)

    both = fetch_all(client, upload_id, source=["rule:executable_download", "window:stat"], limit=200)
    only_rule = fetch_all(client, upload_id, source=["rule:executable_download"], limit=200)

    assert {e["line_no"] for e in both} == {e["line_no"] for e in exe} | {e["line_no"] for e in stat}
    assert [e["line_no"] for e in only_rule] == [e["line_no"] for e in exe]
    assert client.get(f"/api/uploads/{upload_id}/events", params={"source": "rule:drop_tables"}).status_code == 422


def test_histogram_buckets_add_up_and_follow_the_filters(client, upload_id):
    h = client.get(f"/api/uploads/{upload_id}/events/histogram").json()
    total = client.get(f"/api/uploads/{upload_id}/events/count").json()["total"]

    assert h["bucket_minutes"] == 60  # one generated week
    times = [p["ts"] for p in h["points"]]
    assert times == sorted(times) and len(times) == len(set(times))
    assert sum(p["total"] for p in h["points"]) == total
    assert any(p["total"] == 0 for p in h["points"])  # gap-filled quiet hours
    assert all(p["blocked"] <= p["total"] and p["flagged"] <= p["total"] for p in h["points"])

    blocked = client.get(f"/api/uploads/{upload_id}/events/histogram", params={"action": "Blocked"}).json()
    assert sum(p["total"] for p in blocked["points"]) == sum(p["blocked"] for p in h["points"])
    assert client.get(f"/api/uploads/{upload_id}/events/histogram", params={"q": "no-such-thing-xyz"}).json()["points"] == []


def test_histogram_zoom_gets_finer_buckets_across_the_whole_window(client, upload_id):
    """D123: a 1-hour time filter gives 1-minute bars covering the full hour (not one hourly bar)."""
    first = client.get(f"/api/uploads/{upload_id}/events", params={"limit": 1}).json()["items"][0]["ts"]
    start = datetime.fromisoformat(first).replace(minute=0, second=0, microsecond=0)
    params = {"start": start.isoformat(), "end": (start + timedelta(hours=1)).isoformat()}
    h = client.get(f"/api/uploads/{upload_id}/events/histogram", params=params).json()
    count = client.get(f"/api/uploads/{upload_id}/events/count", params=params).json()["total"]

    assert h["bucket_minutes"] == 1
    assert len(h["points"]) == 60  # 11:00 ... 11:59, the end is exclusive
    assert datetime.fromisoformat(h["points"][0]["ts"]) == start
    assert sum(p["total"] for p in h["points"]) == count > 0
