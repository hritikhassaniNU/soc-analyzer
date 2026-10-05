import dataclasses
from datetime import UTC, datetime

import pytest

from app.parsing.event import ZscalerEvent, derive_host
from app.parsing.fields import CSV_COLUMNS, REQUIRED_COLUMNS


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("mega.nz/upload?x=1", "mega.nz"),                 # typical Zscaler: no scheme
        ("https://mega.nz/upload", "mega.nz"),             # with scheme
        ("WWW.Example.COM/Path", "www.example.com"),       # lowercased
        ("example.com:8443/admin", "example.com"),         # port stripped
        ("user:pw@example.com/x", "example.com"),          # userinfo stripped
        ("10.1.4.22:8080/api", "10.1.4.22"),               # IPv4
        ("[2001:db8::1]:443/x", "2001:db8::1"),            # IPv6 brackets removed
        ("", None),
        ("[::1", None),                                    # malformed IPv6 -> None, no crash
    ],
)
def test_derive_host(url, host):
    assert derive_host(url) == host


def _event() -> ZscalerEvent:
    return ZscalerEvent(
        line_no=1, ts=datetime(2026, 1, 1, tzinfo=UTC), username="jdoe", client_ip="10.0.0.1",
        url="example.com/", host="example.com", action="Allowed", risk_score=0,
        bytes_out=10, bytes_in=20,
    )


def test_event_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _event().username = "attacker"  # type: ignore[misc]


def test_event_instances_use_slots_not_a_dict():
    assert not hasattr(_event(), "__dict__")  # slots: fixed attributes, less memory per event


def test_layout_has_22_unique_columns_and_required_ones_exist():
    assert len(CSV_COLUMNS) == 22  # 20 original + device, device_os (appended, optional)
    assert len(set(CSV_COLUMNS)) == 22
    assert REQUIRED_COLUMNS <= set(CSV_COLUMNS)
