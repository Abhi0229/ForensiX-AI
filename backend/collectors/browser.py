"""Browser history collector for ForensiX AI.

Reads local browser history databases (read-only) and converts each history
record into the common ForensiX ``Event`` structure via the shared normalizer.
It never writes to the ForensiX database and never modifies the browser's own
database.

    Browser history DB (Chrome/Edge = Chromium 'History', Firefox 'places.sqlite')
            |
    _read_sqlite_history()   ->  raw record dicts   (safe copy + read-only)
            |
    _build_raw_event()        ->  raw event dict     (pure, testable)
            |
    normalize_event()         ->  common Event object
            |
    (caller stores it)

Supported browsers: Google Chrome, Microsoft Edge (both Chromium), and Mozilla
Firefox. Missing browsers/profiles/databases are handled gracefully; one
browser failing never stops the others.

Safety: browser databases are opened read-only after copying to a temporary
file (the live DB is frequently locked by a running browser and must never be
altered). Temp copies are always cleaned up. URLs and titles are treated only
as data -- nothing is opened, executed, or launched.

Forensic note: a history record evidences that the browser *recorded* a visit
to a URL. It does not by itself prove a specific person viewed the page or
acted intentionally. Browser + profile are preserved so investigators can
trace each record to its source.
"""

import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

from backend.processing.normalizer import normalize_event

# ForensiX source label and event type for every record this collector emits.
SOURCE = "Browser"
EVENT_TYPE = "BROWSER_VISIT"
DEFAULT_SEVERITY = "INFO"
DEFAULT_MAX_EVENTS = 100

# Chromium stores timestamps as microseconds since 1601-01-01 UTC (the Windows
# FILETIME / WebKit epoch). Firefox stores microseconds since the Unix epoch.
_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Chromium 'urls' table: newest visits first.
_CHROMIUM_QUERY = (
    "SELECT url, title, visit_count, last_visit_time "
    "FROM urls ORDER BY last_visit_time DESC LIMIT ?"
)
# Firefox 'moz_places' table: newest visits first, skipping never-visited rows.
_FIREFOX_QUERY = (
    "SELECT url, title, visit_count, last_visit_date "
    "FROM moz_places WHERE last_visit_date IS NOT NULL "
    "ORDER BY last_visit_date DESC LIMIT ?"
)


def chromium_time_to_datetime(value) -> Optional[datetime]:
    """Convert a Chromium timestamp (microseconds since 1601-01-01 UTC).

    Returns a naive UTC datetime, or None for missing/zero/invalid input.
    Chrome and Edge share this format.
    """
    if not value:
        return None
    try:
        dt = _CHROMIUM_EPOCH + timedelta(microseconds=int(value))
        return dt.replace(tzinfo=None)
    except (ValueError, OverflowError, TypeError):
        return None


def firefox_time_to_datetime(value) -> Optional[datetime]:
    """Convert a Firefox timestamp (microseconds since Unix epoch, UTC).

    Returns a naive UTC datetime, or None for missing/zero/invalid input.
    """
    if not value:
        return None
    try:
        dt = _UNIX_EPOCH + timedelta(microseconds=int(value))
        return dt.replace(tzinfo=None)
    except (ValueError, OverflowError, TypeError):
        return None


def _current_user() -> str:
    """Best-effort current Windows user; empty if unavailable (not guessed)."""
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def _hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return ""


def _build_raw_event(record: dict, browser: str, profile: str,
                     device: Optional[str] = None,
                     user: Optional[str] = None) -> dict:
    """Map a browser history record to a raw ForensiX event dict.

    Pure and side-effect free. ``record`` uses plain keys (url, title,
    visit_count, timestamp). Missing fields become empty/None rather than
    fabricated. Returns a dict suitable for ``normalize_event(..., source=SOURCE)``.
    """
    url = (record.get("url") or "").strip()
    title = (record.get("title") or "").strip()
    visit_count = record.get("visit_count")
    timestamp = record.get("timestamp")  # already a datetime or None

    label = title or url or "(no title)"
    description = f"{browser} visited: {label}"

    metadata = {
        "browser": browser,
        "profile": profile,
        "url": url,
        "title": title,
        "visit_count": visit_count,
    }
    metadata = {key: value for key, value in metadata.items() if value not in (None, "")}

    return {
        # If the browser timestamp was unparseable, omit it and let the
        # normalizer default to now() rather than inventing a visit time.
        "timestamp": timestamp,
        "source": SOURCE,
        "event_type": EVENT_TYPE,
        "description": description,
        "severity": DEFAULT_SEVERITY,
        "user": user if user is not None else _current_user(),
        "device": device if device is not None else _hostname(),
        "file_path": url,  # URL stored as the source-specific object/location
        "metadata": metadata,
    }


def record_to_forensix(record: dict, browser: str, profile: str,
                       device: Optional[str] = None, user: Optional[str] = None):
    """Convert a browser history record to a normalized ForensiX Event."""
    raw = _build_raw_event(record, browser, profile, device=device, user=user)
    return normalize_event(raw, source=SOURCE)


def _read_sqlite_history(db_path: str, query: str,
                         row_mapper: Callable[[tuple], dict],
                         max_events: int = DEFAULT_MAX_EVENTS) -> List[dict]:
    """Safely read history rows from a (possibly locked) SQLite database.

    The live database is first copied to a temporary file (including any -wal
    and -shm sidecar files) and then opened strictly read-only. The original
    database is never touched. Malformed rows are skipped. The temporary copy
    is always removed.

    Raises:
        FileNotFoundError: if ``db_path`` does not exist.
        sqlite3.DatabaseError: if the copy cannot be read as a database
            (e.g. corrupted). Callers handle this per-browser.
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(db_path)

    tmp_dir = tempfile.mkdtemp(prefix="forensix_browser_")
    tmp_db = os.path.join(tmp_dir, "history.sqlite")
    try:
        shutil.copy2(db_path, tmp_db)
        # Copy WAL/SHM sidecars if present so recent visits are visible.
        for suffix in ("-wal", "-shm"):
            side = db_path + suffix
            if os.path.isfile(side):
                try:
                    shutil.copy2(side, tmp_db + suffix)
                except OSError:
                    pass

        records: List[dict] = []
        # Read-only URI connection on the COPY (defence in depth).
        uri = f"file:{tmp_db}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            cursor = connection.execute(query, (max_events,))
            for row in cursor:
                try:
                    mapped = row_mapper(row)
                except Exception:
                    # Skip a malformed/unexpected row, keep the rest.
                    continue
                if mapped is not None:
                    records.append(mapped)
        finally:
            connection.close()
        return records
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _chromium_row_mapper(row: tuple) -> dict:
    url, title, visit_count, last_visit_time = row
    return {
        "url": url,
        "title": title,
        "visit_count": visit_count,
        "timestamp": chromium_time_to_datetime(last_visit_time),
    }


def _firefox_row_mapper(row: tuple) -> dict:
    url, title, visit_count, last_visit_date = row
    return {
        "url": url,
        "title": title,
        "visit_count": visit_count,
        "timestamp": firefox_time_to_datetime(last_visit_date),
    }


# --- Profile discovery ------------------------------------------------------
# Base directories are resolved from the current user's environment; none are
# hardcoded to a specific username. Each discovery function accepts an explicit
# base directory so tests can point it at a temporary layout.

def _chromium_user_data_dir(vendor_path: str) -> Optional[str]:
    """Return the Chromium 'User Data' dir for a vendor, or None."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    path = os.path.join(local, *vendor_path.split("/"), "User Data")
    return path if os.path.isdir(path) else None


def discover_chromium_profiles(user_data_dir: str) -> List[Dict[str, str]]:
    """Find profiles with a History DB under a Chromium 'User Data' dir.

    Returns a list of {"profile": name, "db_path": path}. A profile is any
    subdirectory (Default, Profile 1, ...) that contains a 'History' file.
    """
    profiles: List[Dict[str, str]] = []
    if not user_data_dir or not os.path.isdir(user_data_dir):
        return profiles
    try:
        entries = sorted(os.listdir(user_data_dir))
    except OSError:
        return profiles
    for entry in entries:
        profile_dir = os.path.join(user_data_dir, entry)
        history = os.path.join(profile_dir, "History")
        if os.path.isdir(profile_dir) and os.path.isfile(history):
            profiles.append({"profile": entry, "db_path": history})
    return profiles


def discover_firefox_profiles(profiles_dir: Optional[str] = None) -> List[Dict[str, str]]:
    """Find Firefox profiles containing places.sqlite.

    Returns a list of {"profile": name, "db_path": path}. Defaults to
    %APPDATA%/Mozilla/Firefox/Profiles when ``profiles_dir`` is not given.
    """
    if profiles_dir is None:
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return []
        profiles_dir = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
    profiles: List[Dict[str, str]] = []
    if not os.path.isdir(profiles_dir):
        return profiles
    try:
        entries = sorted(os.listdir(profiles_dir))
    except OSError:
        return profiles
    for entry in entries:
        places = os.path.join(profiles_dir, entry, "places.sqlite")
        if os.path.isfile(places):
            profiles.append({"profile": entry, "db_path": places})
    return profiles


def _collect_from_profiles(profiles, browser, query, row_mapper,
                           max_events, normalize):
    """Read + normalize history for a list of discovered profiles.

    A profile that fails (missing/locked/corrupted DB, permission error) is
    skipped without aborting the others.
    """
    collected = []
    device, user = _hostname(), _current_user()
    for entry in profiles:
        try:
            records = _read_sqlite_history(
                entry["db_path"], query, row_mapper, max_events=max_events
            )
        except (FileNotFoundError, PermissionError, sqlite3.Error, OSError):
            continue
        for record in records:
            raw = _build_raw_event(record, browser, entry["profile"],
                                   device=device, user=user)
            if normalize:
                try:
                    collected.append(normalize_event(raw, source=SOURCE))
                except Exception:
                    continue
            else:
                collected.append(raw)
    return collected


def collect_chrome(max_events: int = DEFAULT_MAX_EVENTS, normalize: bool = True,
                   user_data_dir: Optional[str] = None) -> list:
    """Collect Chrome history across all profiles. Empty list if not installed."""
    user_data_dir = user_data_dir or _chromium_user_data_dir("Google/Chrome")
    profiles = discover_chromium_profiles(user_data_dir) if user_data_dir else []
    return _collect_from_profiles(profiles, "Chrome", _CHROMIUM_QUERY,
                                  _chromium_row_mapper, max_events, normalize)


def collect_edge(max_events: int = DEFAULT_MAX_EVENTS, normalize: bool = True,
                 user_data_dir: Optional[str] = None) -> list:
    """Collect Edge history across all profiles. Empty list if not installed."""
    user_data_dir = user_data_dir or _chromium_user_data_dir("Microsoft/Edge")
    profiles = discover_chromium_profiles(user_data_dir) if user_data_dir else []
    return _collect_from_profiles(profiles, "Edge", _CHROMIUM_QUERY,
                                  _chromium_row_mapper, max_events, normalize)


def collect_firefox(max_events: int = DEFAULT_MAX_EVENTS, normalize: bool = True,
                    profiles_dir: Optional[str] = None) -> list:
    """Collect Firefox history across all profiles. Empty list if not installed."""
    profiles = discover_firefox_profiles(profiles_dir)
    return _collect_from_profiles(profiles, "Firefox", _FIREFOX_QUERY,
                                  _firefox_row_mapper, max_events, normalize)


# Dispatch table so callers can select a subset of browsers by name.
_BROWSER_COLLECTORS = {
    "chrome": collect_chrome,
    "edge": collect_edge,
    "firefox": collect_firefox,
}


def collect_browser_history(browsers=None, max_events: int = DEFAULT_MAX_EVENTS,
                            normalize: bool = True) -> list:
    """Collect history from the requested browsers as ForensiX Events.

    Each browser is collected independently; one failing never prevents the
    others. Returns an empty list when no supported browser has readable
    history.

    Args:
        browsers: Iterable of browser names ("chrome", "edge", "firefox").
            Defaults to all supported browsers.
        max_events: Maximum records per profile.
        normalize: When True (default) return Event objects; when False return
            the raw event dicts.
    """
    if browsers is None:
        browsers = tuple(_BROWSER_COLLECTORS)

    collected = []
    for name in browsers:
        collector = _BROWSER_COLLECTORS.get(str(name).lower())
        if collector is None:
            continue
        try:
            collected.extend(collector(max_events=max_events, normalize=normalize))
        except Exception:
            # Defence in depth: a browser collector must never break the rest.
            continue
    return collected
