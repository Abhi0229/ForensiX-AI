"""Gated live-system smoke test (STEP 4) -- OPT-IN, READ-ONLY.

Skipped by default. Runs only when FORENSIX_RUN_LIVE_TESTS=1 so CI and normal
`pytest` runs never depend on live Windows/USB/browser state. Every collector
is invoked read-only with a small bounded event cap; a collector that is
unavailable on this machine is skipped, never failed. Nothing is written,
deleted, or modified on the host, and no event is persisted to any database --
this test only proves the live collectors return well-formed Event objects.
"""

import os

import pytest

from backend.collectors import browser as browser_mod
from backend.collectors import defender as def_mod
from backend.collectors import usb as usb_mod
from backend.collectors import windows_events as win_mod
from backend.database.models import Event

pytestmark = pytest.mark.skipif(
    os.environ.get("FORENSIX_RUN_LIVE_TESTS") != "1",
    reason="live-system test; set FORENSIX_RUN_LIVE_TESTS=1 to enable",
)

_MAX = 10  # bounded: never enumerate the whole host


def _assert_events(events, expected_source):
    assert isinstance(events, list)
    for ev in events:
        assert isinstance(ev, Event)
        assert ev.source == expected_source
        assert ev.event_type
        # Timestamps are never fabricated; when present they are datetimes.
        if ev.timestamp is not None:
            assert hasattr(ev.timestamp, "year")


def test_live_windows_events_conform():
    try:
        events = win_mod.collect_windows_events(max_events=_MAX)
    except Exception as exc:                      # unavailable collector
        pytest.skip(f"windows events unavailable: {exc}")
    if not events:
        pytest.skip("no windows events available on this host")
    assert len(events) <= _MAX * len(win_mod.DEFAULT_CHANNELS)
    _assert_events(events, "Windows")


def test_live_defender_events_conform():
    try:
        events = def_mod.collect_defender_events(max_events=_MAX)
    except Exception as exc:
        pytest.skip(f"defender events unavailable: {exc}")
    if not events:
        pytest.skip("no defender events available on this host")
    assert len(events) <= _MAX
    _assert_events(events, "Defender")


def test_live_usb_devices_conform():
    try:
        events = usb_mod.enumerate_usb_devices()
    except Exception as exc:
        pytest.skip(f"usb enumeration unavailable: {exc}")
    if not events:
        pytest.skip("no usb devices enumerated on this host")
    _assert_events(events, "USB")


def test_live_browser_history_conforms():
    try:
        events = browser_mod.collect_browser_history(max_events=_MAX)
    except Exception as exc:
        pytest.skip(f"browser history unavailable: {exc}")
    if not events:
        pytest.skip("no browser history available on this host")
    assert len(events) <= _MAX * 8      # a few browsers/profiles, still bounded
    _assert_events(events, "Browser")

