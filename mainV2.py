"""
Sideband Watchtower

FastAPI service that ingests ADS-B (SBS-1) data from dump1090-fa, stores
recent aircraft + events in SQLite, and serves a lightweight dashboard UI.

This file has been *re-ordered for readability* (functions grouped by concern),
without intentionally changing runtime behavior.
"""

# =============================================================================
#  Imports
# =============================================================================
import os
import sqlite3
import socket
import asyncio
import time
import json
import re
import threading

from datetime import datetime
from typing import List, Optional
from math import radians, sin, cos, sqrt, atan2

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

import icao_lookup
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

if load_dotenv is not None:
    load_dotenv()


# =============================================================================
#  App
# =============================================================================
app = FastAPI()


# =============================================================================
#  Configuration
# =============================================================================
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "watchtower.db")

# ADS-B / SBS-1 feed (dump1090-fa)
ADS_B_HOST = os.getenv("ADSB_HOST", "127.0.0.1")
try:
    ADS_B_PORT = int(os.getenv("ADSB_PORT", "30003"))
except ValueError:
    ADS_B_PORT = 30003

# seconds between "contact" events per hex
AIRCRAFT_EVENT_MIN_INTERVAL = 60.0

def _get_float_env(name: str, default: float) -> float:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default

RECEIVER_LAT = _get_float_env("RECEIVER_LAT", 0.0)
RECEIVER_LON = _get_float_env("RECEIVER_LON", 0.0)
RECEIVER_COORDS_CONFIGURED = bool(
    (os.getenv("RECEIVER_LAT", "") or "").strip()
    and (os.getenv("RECEIVER_LON", "") or "").strip()
)

# In-memory state: throttling + behavior detection + freshness
_last_aircraft_event_ts: dict[str, float] = {}
_recent_positions: dict[str, list[tuple[float, float, float]]] = {}
_last_loiter_event_ts: dict[str, float] = {}
_last_rapid_vs_event_ts: dict[str, float] = {}
_aircraft_last_alt: dict[str, tuple[Optional[int], float]] = {}
_aircraft_last_update_ts: dict[str, float] = {}  # for "active" vs "stale"


# =============================================================================
#  Database layer (SQLite)
# =============================================================================
def get_db() -> sqlite3.Connection:
    """
    Open a SQLite connection with Row objects so we can access columns by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_aircraft_extra_columns() -> None:
    """
    Make sure the 'aircraft' table has the new 'tags' and 'interesting_score'
    columns. Safe to call on every startup.
    """
    conn = get_db()
    try:
        cur = conn.execute("PRAGMA table_info(aircraft)")
        cols = {row["name"] for row in cur.fetchall()}

        if "tags" not in cols:
            conn.execute("ALTER TABLE aircraft ADD COLUMN tags TEXT")
        if "interesting_score" not in cols:
            conn.execute("ALTER TABLE aircraft ADD COLUMN interesting_score REAL DEFAULT 0.0")

        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """
    Create tables if they don't exist yet.
    """
    schema = """
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source    TEXT NOT NULL,
        channel   TEXT,
        latitude  REAL,
        longitude REAL,
        payload   TEXT,
        severity  TEXT
    );

    CREATE TABLE IF NOT EXISTS aircraft (
        hex          TEXT PRIMARY KEY,
        callsign     TEXT,
        last_seen    TEXT NOT NULL,
        altitude     INTEGER,
        ground_speed REAL,
        track        REAL,
        latitude     REAL,
        longitude    REAL,
        tags         TEXT,
        interesting_score REAL        
    );

    CREATE TABLE IF NOT EXISTS aircraft_meta (
        hex           TEXT PRIMARY KEY,
        registration  TEXT,
        manufacturer  TEXT,
        model         TEXT,
        typecode      TEXT,
        operator      TEXT,
        country       TEXT,
        last_lookup   TEXT
    );
    """
    conn = get_db()
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
        ensure_aircraft_extra_columns()


# =============================================================================
#  Aircraft metadata cache (OpenSky via icao_lookup.py)
# =============================================================================
def ensure_aircraft_metadata(hex_ident: str) -> None:
    """
    Ensure we have static metadata for this ICAO hex in aircraft_meta.
    Uses icao_lookup.py / OpenSky and stores results in SQLite.
    Only hits the API the first time we see a hex (or when we update).
    """
    hex_ident = hex_ident.strip().upper()
    if not hex_ident:
        return

    # Already have it?
    conn = get_db()
    try:
        cur = conn.execute(
            "SELECT hex FROM aircraft_meta WHERE hex = ?",
            (hex_ident,),
        )
        if cur.fetchone():
            return
    finally:
        conn.close()

    # No existing record → call OpenSky via icao_lookup.py
    try:
        token = icao_lookup.get_token()
    except Exception:
        return

    if not token:
        return

    try:
        meta = icao_lookup.get_aircraft_meta(token, hex_ident)
    except Exception:
        return

    if not meta:
        return

    reg = meta.get("registration")
    manufacturer = meta.get("manufacturerName")
    model = meta.get("model")
    typecode = meta.get("typecode")
    operator = meta.get("operator")
    country = meta.get("country")
    ts_str = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO aircraft_meta
                (hex, registration, manufacturer, model, typecode, operator,
                 country, last_lookup)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hex) DO UPDATE SET
                registration = excluded.registration,
                manufacturer = excluded.manufacturer,
                model        = excluded.model,
                typecode     = excluded.typecode,
                operator     = excluded.operator,
                country      = excluded.country,
                last_lookup  = excluded.last_lookup;
            """,
            (
                hex_ident,
                reg,
                manufacturer,
                model,
                typecode,
                operator,
                country,
                ts_str,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_aircraft_meta_summary(hex_ident: str) -> dict:
    """
    Return a merged dict of (aircraft table + aircraft_meta table) for a hex.
    """
    hex_ident = (hex_ident or "").strip().upper()
    if not hex_ident:
        return {}

    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT
                a.hex,
                a.callsign,
                a.last_seen,
                a.altitude,
                a.ground_speed,
                a.track,
                a.latitude,
                a.longitude,
                a.tags,
                a.interesting_score,
                m.registration,
                m.manufacturer,
                m.model,
                m.typecode,
                m.operator,
                m.country,
                m.last_lookup
            FROM aircraft AS a
            LEFT JOIN aircraft_meta AS m
                ON m.hex = a.hex
            WHERE a.hex = ?
            """,
            (hex_ident,),
        )
        row = cur.fetchone()
        if not row:
            return {}
        return dict(row)
    finally:
        conn.close()


# =============================================================================
#  Tagging / scoring / role summaries
# =============================================================================
def classify_aircraft_tags_and_score(row: sqlite3.Row) -> tuple[list[str], float]:
    """
    Given a joined aircraft + aircraft_meta row, return (tags, score).

    Expected fields in row:
      a.hex, a.callsign, a.altitude, a.ground_speed, a.latitude, a.longitude,
      m.registration, m.model, m.typecode, m.operator, m.country
    """
    tags: list[str] = []
    score = 0.0

    hex_code = (row["hex"] or "").upper()
    callsign = (row["callsign"] or "").upper()
    reg = (row["registration"] or "").upper()
    model = (row["model"] or "").upper()
    typecode = (row["typecode"] or "").upper()
    operator = (row["operator"] or "").upper()
    country = (row["country"] or "").upper()

    # ------------------------------------------------------------------
    # Base type tag (helicopter vs fixed-wing)
    # ------------------------------------------------------------------
    if typecode.startswith("H") or "HELICOPTER" in model:
        tags.append("helicopter")
    else:
        tags.append("fixed-wing")

    # ------------------------------------------------------------------
    # Military heuristics
    # ------------------------------------------------------------------
    is_mil = False
    if hex_code.startswith("AE"):
        is_mil = True

    if any(k in operator for k in (
        "USAF", "U.S. AIR FORCE", "AIR FORCE", "US ARMY", "U.S. ARMY",
        "US NAVY", "USMC", "MARINES", "ANG", "NATIONAL GUARD", "USCG"
    )):
        is_mil = True

    if is_mil:
        tags.append("military")
        score += 40.0

    # ------------------------------------------------------------------
    # Government & law-enforcement heuristics
    # ------------------------------------------------------------------
    is_gov = False
    is_le = False

    if any(k in operator for k in (
        "DEPT", "DEPARTMENT", "HOMELAND", "CUSTOMS", "BORDER", "CBP", "DHS",
        "JUSTICE", "NASA"
    )):
        is_gov = True

    if any(k in operator for k in (
        "POLICE", "STATE POLICE", "SHERIFF", "HIGHWAY PATROL", "TROOPER"
    )):
        is_le = True

    if is_gov:
        tags.append("government")
        score += 25.0

    if is_le:
        tags.append("law-enforcement")
        score += 25.0

    # ------------------------------------------------------------------
    # Cargo heuristics
    # ------------------------------------------------------------------
    is_cargo = False

    if any(k in operator for k in (
        "FEDEX", "FEDERAL EXPRESS", "UPS", "UNITED PARCEL", "DHL", "ATLAS AIR",
        "KALITTA", "ATLAS", "CARGO", "PRIME AIR", "AMAZON"
    )):
        is_cargo = True

    # obvious cargo types like C130/C17/C5 etc
    if typecode.startswith("C13") or typecode.startswith("C17") or typecode.startswith("C5"):
        is_cargo = True

    if is_cargo:
        tags.append("cargo")
        score += 15.0

    # ------------------------------------------------------------------
    # Airline / bizjet / GA heuristics
    # ------------------------------------------------------------------
    is_bizjet = False

    # Things that almost certainly are bizjets if they appear in model
    bizjet_keywords = (
        "GULFSTREAM", "GLF", "CITATION", "LEARJET", "CHALLENGER", "FALCON",
        "PHENOM", "LEGACY", "HAWKER", "BEECHJET"
    )
    if any(k in model for k in bizjet_keywords):
        is_bizjet = True

    # Common bizjet model prefixes from ICAO / type designations
    bizjet_prefixes = (
        "GLF", "CL6", "CL3", "LJ", "C56X", "C550", "C525", "C680", "C68A",
        "C700", "C750", "FA7X", "F2TH", "F900", "E50P", "E55P", "680A"
    )
    if any(model.startswith(prefix) for prefix in bizjet_prefixes):
        is_bizjet = True

    # Some ICAO type codes that are definitely bizjets
    bizjet_typecodes = (
        "C25A", "C25B", "C25C", "C56X", "C68A", "C680", "C700",
        "GLF4", "GLF5", "GLF6", "FA7X", "F2TH"
    )
    if typecode in bizjet_typecodes:
        is_bizjet = True

    # If we decided it's a bizjet
    if is_bizjet:
        tags.append("bizjet")
        score += 10.0
    else:
        # Not a bizjet / mil / gov / LE / cargo: classify as airline or GA
        if not is_mil and not is_gov and not is_le and not is_cargo:
            # If we have an operator, assume normal airline/GA traffic.
            # If operator is blank but the model clearly looks GA (PC-12, TBM,
            # King Air, Cirrus, etc.), also treat it as GA instead of "unknown".
            ga_keywords = (
                "PC-12", "PC12", "TBM", "CARAVAN", "C208", "KING AIR", "B200",
                "PIPER", "CESSNA", "BEECH", "SR22", "SR20", "M20", "DA40", "DA42"
            )
            looks_ga = any(k in model for k in ga_keywords)

            if operator or looks_ga:
                tags.append("airline-or-ga")
            else:
                tags.append("unknown")

    # ------------------------------------------------------------------
    # Small bonuses
    # ------------------------------------------------------------------
    # Helicopters are locally interesting
    if "helicopter" in tags:
        score += 5.0

    # Small bonus if callsign looks mil-style (no common airline prefix)
    if is_mil and callsign and not any(callsign.startswith(p) for p in (
        "AA", "DL", "UA", "SW", "WN", "B6", "FR", "EZ"
    )):
        score += 5.0

    # Deduplicate & sort tags for stable output
    tags = sorted(set(tags))

    return tags, score


def summarize_aircraft_role(tags: List[str], operator: str, model: str) -> str:
    """
    Lightweight role summary for UI labels.
    """
    tags = tags or []
    operator_u = (operator or "").upper()
    model_u = (model or "").upper()

    if "military" in tags:
        return "Military"
    if "law-enforcement" in tags:
        return "Law Enforcement"
    if "government" in tags:
        return "Government"
    if "cargo" in tags:
        return "Cargo"
    if "bizjet" in tags:
        return "Business Jet"
    if "helicopter" in tags:
        if any(k in operator_u for k in ("MED", "EMS", "LIFE", "HOSP", "HEALTH")):
            return "Medevac Helo"
        return "Helicopter"

    # fallback guesses
    if any(k in operator_u for k in ("AIRLINES", "AIR LINE", "AIRWAYS")):
        return "Airliner"
    if any(k in model_u for k in ("CESSNA", "PIPER", "BEECH", "CIRRUS")):
        return "General Aviation"

    return "Other"


def update_aircraft_tags_and_score(hex_ident: str) -> None:
    """
    Recompute and store tags + interesting_score for an aircraft using
    the joined aircraft + meta row.
    """
    hex_ident = (hex_ident or "").strip().upper()
    if not hex_ident:
        return

    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT
                a.hex,
                a.callsign,
                a.altitude,
                a.ground_speed,
                a.latitude,
                a.longitude,
                m.registration,
                m.model,
                m.typecode,
                m.operator,
                m.country
            FROM aircraft AS a
            LEFT JOIN aircraft_meta AS m
                ON m.hex = a.hex
            WHERE a.hex = ?
            """,
            (hex_ident,),
        )
        row = cur.fetchone()
        if not row:
            return

        tags, score = classify_aircraft_tags_and_score(row)

        conn.execute(
            """
            UPDATE aircraft
            SET tags = ?, interesting_score = ?
            WHERE hex = ?
            """,
            (",".join(tags), score, hex_ident),
        )
        conn.commit()
    finally:
        conn.close()


# =============================================================================
#  Utility helpers (distance, events, status)
# =============================================================================
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Distance in km between two lat/lon points.
    """
    R = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


def fetch_recent_events(limit: int = 50):
    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT id, timestamp, source, channel, latitude, longitude, payload, severity
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        return rows
    finally:
        conn.close()


def extract_adsb_ident_from_payload(payload: str) -> Optional[str]:
    """
    Try to pull ICAO hex from an event payload (if it contains "hex=ABC123").
    """
    if not payload:
        return None
    m = re.search(r"\bhex=([0-9A-Fa-f]{6})\b", payload)
    if not m:
        return None
    return m.group(1).upper()


def insert_test_event():
    conn = get_db()
    try:
        ts_str = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        conn.execute(
            """
            INSERT INTO events (timestamp, source, channel, latitude, longitude, payload, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts_str,
                "test",
                "watchtower",
                RECEIVER_LAT,
                RECEIVER_LON,
                "This is a test event generated by /add-test-event",
                "info",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_basic_status() -> dict:
    """
    Return a dict of counts + lightweight system health for /status.
    """
    conn = get_db()
    try:
        cur = conn.execute("SELECT COUNT(*) AS n FROM events")
        total_events = cur.fetchone()["n"]
        cur = conn.execute("SELECT COUNT(*) AS n FROM aircraft")
        total_aircraft = cur.fetchone()["n"]
        cur = conn.execute("SELECT timestamp FROM events ORDER BY id DESC LIMIT 1")
        last_event = cur.fetchone()
        last_event = last_event["timestamp"] if last_event else None
    finally:
        conn.close()

    cpu_pct = None
    mem_info = None
    disk_info = None

    if psutil:
        try:
            cpu_pct = psutil.cpu_percent(interval=0.1)
            vm = psutil.virtual_memory()
            mem_info = {
                "total": vm.total,
                "available": vm.available,
                "percent": vm.percent,
            }
            du = psutil.disk_usage("/")
            disk_info = {
                "total": du.total,
                "used": du.used,
                "free": du.free,
                "percent": du.percent,
            }
        except Exception:
            pass

    return {
        "db_path": DB_PATH,
        "total_events": total_events,
        "total_aircraft": total_aircraft,
        "last_event": last_event,
        "cpu_percent": cpu_pct,
        "memory": mem_info,
        "disk_root": disk_info,
    }


# =============================================================================
#  ADS-B ingestion + event generation
# =============================================================================
def upsert_aircraft(
    hex_ident: str,
    callsign: Optional[str],
    ts_str: str,
    altitude: Optional[int],
    ground_speed: Optional[float],
    track: Optional[float],
    latitude: Optional[float],
    longitude: Optional[float],
) -> None:
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO aircraft
                (hex, callsign, last_seen, altitude, ground_speed, track,
                 latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hex) DO UPDATE SET
                callsign     = excluded.callsign,
                last_seen    = excluded.last_seen,
                altitude     = excluded.altitude,
                ground_speed = excluded.ground_speed,
                track        = excluded.track,
                latitude     = excluded.latitude,
                longitude    = excluded.longitude;
            """,
            (
                hex_ident,
                callsign,
                ts_str,
                altitude,
                ground_speed,
                track,
                latitude,
                longitude,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # mark last update time for freshness
    _aircraft_last_update_ts[hex_ident] = time.time()

    # Look up static metadata (registration/operator/type) on first sight
    ensure_aircraft_metadata(hex_ident)

    # classify and score this aircraft based on metadata
    update_aircraft_tags_and_score(hex_ident)


def maybe_insert_aircraft_contact_event(
    hex_ident: str,
    callsign: Optional[str],
    ts_str: str,
    latitude: Optional[float],
    longitude: Optional[float],
    altitude: Optional[int],
) -> None:
    """
    Insert a basic "contact" event for an aircraft, with per-hex throttling.
    """
    now = time.time()
    last = _last_aircraft_event_ts.get(hex_ident)
    if last is not None and (now - last) < AIRCRAFT_EVENT_MIN_INTERVAL:
        return

    _last_aircraft_event_ts[hex_ident] = now

    parts = [f"hex={hex_ident}"]
    if callsign:
        parts.append(f"callsign={callsign.strip()}")
    if altitude is not None:
        parts.append(f"alt_ft={altitude}")
    if latitude is not None and longitude is not None:
        dist_km = haversine_km(RECEIVER_LAT, RECEIVER_LON, latitude, longitude)
        parts.append(f"range_km={dist_km:.1f}")

    payload = " ".join(parts)

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO events (timestamp, source, channel, latitude, longitude, payload, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts_str, "adsb", "air", latitude, longitude, payload, "info"),
        )
        conn.commit()
    finally:
        conn.close()


def update_behavior_events(
    hex_ident: str,
    callsign: Optional[str],
    ts_str: str,
    lat: Optional[float],
    lon: Optional[float],
    altitude: Optional[int],
) -> None:
    """
    Track aircraft behavior and generate higher-level events:
      - "loitering": multiple positions within a small radius for a while
      - "rapid VS": large altitude delta over a short period
    """
    now = time.time()

    # ------------------------------------------------------------------
    # Loiter detection (position clustering)
    # ------------------------------------------------------------------
    if lat is not None and lon is not None:
        recent = _recent_positions.setdefault(hex_ident, [])
        recent.append((lat, lon, now))

        # keep only last ~10 minutes
        cutoff = now - 600
        recent[:] = [(a, b, t) for (a, b, t) in recent if t >= cutoff]

        # if we have enough points, compute bounding distance
        if len(recent) >= 8:
            lat0, lon0, _ = recent[0]
            max_km = 0.0
            for (a, b, _) in recent:
                d = haversine_km(lat0, lon0, a, b)
                if d > max_km:
                    max_km = d

            # If stayed within ~2 km for >= 6 minutes, call it loiter
            duration = recent[-1][2] - recent[0][2]
            if duration >= 360 and max_km <= 2.0:
                last_loiter = _last_loiter_event_ts.get(hex_ident)
                if last_loiter is None or (now - last_loiter) >= 900:
                    _last_loiter_event_ts[hex_ident] = now

                    payload = f"hex={hex_ident}"
                    if callsign:
                        payload += f" callsign={callsign.strip()}"
                    payload += f" loiter_s={int(duration)} radius_km={max_km:.2f}"

                    conn = get_db()
                    try:
                        conn.execute(
                            """
                            INSERT INTO events
                                (timestamp, source, channel, latitude, longitude, payload, severity)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (ts_str, "adsb", "behavior", lat, lon, payload, "warning"),
                        )
                        conn.commit()
                    finally:
                        conn.close()

    # ------------------------------------------------------------------
    # Rapid vertical speed detection
    # ------------------------------------------------------------------
    if altitude is not None:
        prev = _aircraft_last_alt.get(hex_ident)
        if prev:
            prev_alt, prev_t = prev
            dt = now - prev_t
            if prev_alt is not None and dt > 0:
                dalt = altitude - prev_alt
                # feet per minute estimate
                fpm = (dalt / dt) * 60.0

                # Rapid climb/descent threshold
                if abs(fpm) >= 3500.0 and dt <= 90.0:
                    last_vs = _last_rapid_vs_event_ts.get(hex_ident)
                    if last_vs is None or (now - last_vs) >= 900:
                        _last_rapid_vs_event_ts[hex_ident] = now

                        payload = f"hex={hex_ident}"
                        if callsign:
                            payload += f" callsign={callsign.strip()}"
                        payload += f" rapid_vs_fpm={int(fpm)} dt_s={int(dt)}"

                        conn = get_db()
                        try:
                            conn.execute(
                                """
                                INSERT INTO events
                                    (timestamp, source, channel, latitude, longitude, payload, severity)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (ts_str, "adsb", "behavior", lat, lon, payload, "warning"),
                            )
                            conn.commit()
                        finally:
                            conn.close()

        _aircraft_last_alt[hex_ident] = (altitude, now)


def process_sbs1_line(line: str) -> None:
    """
    Parse a line from SBS-1 feed and, if it contains a position,
    upsert aircraft + generate events.
    """
    if not line or not line.startswith("MSG"):
        return

    parts = line.split(",")
    if len(parts) < 22:
        return

    # Field indices for SBS-1 "MSG" lines
    #  4 = hexIdent
    # 10 = callsign
    # 11 = altitude
    # 12 = groundSpeed
    # 13 = track
    # 14 = lat
    # 15 = lon
    hex_ident = (parts[4] or "").strip().upper()
    if not hex_ident:
        return

    callsign = (parts[10] or "").strip() or None

    alt = None
    if parts[11]:
        try:
            alt = int(float(parts[11]))
        except Exception:
            alt = None

    gs = None
    if parts[12]:
        try:
            gs = float(parts[12])
        except Exception:
            gs = None

    track = None
    if parts[13]:
        try:
            track = float(parts[13])
        except Exception:
            track = None

    lat = None
    lon = None
    if parts[14] and parts[15]:
        try:
            lat = float(parts[14])
            lon = float(parts[15])
        except Exception:
            lat = None
            lon = None

    # If we don't have a position, skip
    if lat is None or lon is None:
        return

    # Timestamp string – SBS1 includes date/time in multiple columns; we keep simple
    ts_str = datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]

    upsert_aircraft(
        hex_ident=hex_ident,
        callsign=callsign,
        ts_str=ts_str,
        altitude=alt,
        ground_speed=gs,
        track=track,
        latitude=lat,
        longitude=lon,
    )

    # classify and score this aircraft based on metadata
    update_aircraft_tags_and_score(hex_ident)

    # Basic contact event
    maybe_insert_aircraft_contact_event(
        hex_ident=hex_ident,
        callsign=callsign,
        ts_str=ts_str,
        latitude=lat,
        longitude=lon,
        altitude=alt,
    )

    # Behavior-level events (loiter / rapid VS)
    update_behavior_events(
        hex_ident=hex_ident,
        callsign=callsign,
        ts_str=ts_str,
        lat=lat,
        lon=lon,
        altitude=alt,
    )


def adsb_worker_thread():
    """
    Blocking thread that connects to the SBS1 feed (dump1090-fa)
    and feeds each line into process_sbs1_line().

    This is intentionally *not* async so it can't get killed by
    uvicorn's event loop / lifecycle shenanigans.
    """
    while True:
        try:
            print(f"[ADS-B] (thread) connecting to {ADS_B_HOST}:{ADS_B_PORT} ...", flush=True)
            with socket.create_connection((ADS_B_HOST, ADS_B_PORT), timeout=10) as sock:
                print("[ADS-B] (thread) connected.", flush=True)
                f = sock.makefile("r", encoding="ascii", errors="ignore")

                for line in f:
                    text = line.strip()
                    if not text:
                        continue

                    # DEBUG: you can comment this out later if it's too noisy
                    # print(f"[ADS-B] (thread) {text}", flush=True)

                    try:
                        process_sbs1_line(text)
                    except Exception as e:
                        print(f"[ADS-B] (thread) error processing line: {e!r} line={text!r}", flush=True)
                        # don't die on bad lines
                        continue

                print("[ADS-B] (thread) connection closed by peer, will reconnect.", flush=True)

        except Exception as e:
            print(f"[ADS-B] (thread) connection error: {e!r}", flush=True)

        # brief backoff before retrying
        time.sleep(5)


# =============================================================================
#  Startup hook
# =============================================================================
@app.on_event("startup")
async def startup_event():
    init_db()
    print(f"[Startup] ADS-B feed target: {ADS_B_HOST}:{ADS_B_PORT}", flush=True)
    if RECEIVER_COORDS_CONFIGURED:
        print(
            f"[Startup] Receiver coordinates configured: ({RECEIVER_LAT:.5f}, {RECEIVER_LON:.5f})",
            flush=True,
        )
    else:
        print(
            "[Startup] Receiver coordinates are not configured. Map will use placeholder "
            "coordinates. Set RECEIVER_LAT and RECEIVER_LON in .env.",
            flush=True,
        )
    if icao_lookup.opensky_enrichment_enabled():
        print("[Startup] OpenSky enrichment: enabled (credentials provided).", flush=True)
    else:
        print("[Startup] OpenSky enrichment: disabled (no credentials configured).", flush=True)

    # start ADS-B worker thread
    t = threading.Thread(
        target=adsb_worker_thread,
        name="adsb-worker",
        daemon=True,
    )
    t.start()

    # keep any other startup stuff you already have
    ...


# =============================================================================
#  Routes: HTML UI
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    events = fetch_recent_events(limit=100)

    rows_html = ""
    for ev in events:
        severity = (ev["severity"] or "").lower()
        if severity == "critical":
            sev_class = "sev-critical"
        elif severity == "warning":
            sev_class = "sev-warning"
        elif severity == "info":
            sev_class = "sev-info"
        else:
            sev_class = "sev-other"

        payload = ev["payload"] or ""
        ts = ev["timestamp"] or ""
        src = ev["source"] or ""
        chan = ev["channel"] or ""

        # Make hex clickable if we can parse it out
        ident = extract_adsb_ident_from_payload(payload)
        if ident:
            payload_html = (
                f'<a class="hex-link" href="/aircraft/{ident}">{payload}</a>'
            )
        else:
            payload_html = payload

        rows_html += f"""
        <tr class="{sev_class}">
          <td class="ts">{ts}</td>
          <td class="src">{src}</td>
          <td class="chan">{chan}</td>
          <td class="payload">{payload_html}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Sideband Watchtower</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <link rel="stylesheet"
            href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
            integrity="sha256-o9N1j7kP6kGZQ8tOZcH0c2q3E8O5pQvWQY6GkGmJb9A="
            crossorigin=""/>

      <style>
        body {{
          background: #0b0f14;
          color: #f4f8ff;
          font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          margin: 0;
        }}
        header {{
          padding: 14px 16px;
          background: linear-gradient(90deg, #0b0f14, #0d1522);
          border-bottom: 1px solid rgba(255,255,255,0.08);
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }}
        header h1 {{
          margin: 0;
          font-size: 18px;
          letter-spacing: 0.5px;
        }}
        header .right {{
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
        }}
        .pill {{
          padding: 6px 10px;
          border-radius: 999px;
          font-size: 12px;
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.10);
        }}
        .btn {{
          padding: 8px 12px;
          border-radius: 10px;
          border: 1px solid rgba(255,255,255,0.14);
          background: rgba(0,216,255,0.10);
          color: #dffbff;
          font-weight: 650;
          text-decoration: none;
          cursor: pointer;
        }}
        .btn:hover {{
          background: rgba(0,216,255,0.18);
        }}
        main {{
          display: grid;
          grid-template-columns: 1.15fr 0.85fr;
          gap: 12px;
          padding: 12px;
        }}
        @media (max-width: 1100px) {{
          main {{
            grid-template-columns: 1fr;
          }}
        }}

        .card {{
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.10);
          border-radius: 14px;
          padding: 12px;
          box-shadow: 0 0 0 1px rgba(0,0,0,0.2);
        }}

        #map {{
          height: 420px;
          border-radius: 12px;
          overflow: hidden;
          border: 1px solid rgba(255,255,255,0.08);
        }}

        table {{
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }}
        th, td {{
          padding: 8px 8px;
          border-bottom: 1px solid rgba(255,255,255,0.08);
          vertical-align: top;
        }}
        th {{
          text-align: left;
          color: rgba(255,255,255,0.75);
          font-weight: 700;
          letter-spacing: 0.2px;
          font-size: 12px;
        }}
        .ts {{
          width: 170px;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
          font-size: 12px;
          color: rgba(255,255,255,0.75);
        }}
        .src {{
          width: 70px;
          color: rgba(255,255,255,0.75);
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
          font-size: 12px;
        }}
        .chan {{
          width: 90px;
          color: rgba(255,255,255,0.75);
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
          font-size: 12px;
        }}
        .payload {{
          font-size: 13px;
        }}

        .sev-critical td {{
          background: rgba(255, 0, 80, 0.08);
        }}
        .sev-warning td {{
          background: rgba(255, 190, 0, 0.06);
        }}
        .sev-info td {{
          background: rgba(0, 216, 255, 0.05);
        }}

        .hex-link {{
          color: #00d8ff;
          text-decoration: none;
          font-weight: 650;
        }}
        .hex-link:hover {{
          text-decoration: underline;
        }}

        .subhead {{
          display: flex;
          justify-content: space-between;
          align-items: baseline;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 8px;
        }}
        .subhead h2 {{
          margin: 0;
          font-size: 14px;
          letter-spacing: 0.2px;
          color: rgba(255,255,255,0.85);
        }}
        .hint {{
          font-size: 12px;
          color: rgba(255,255,255,0.65);
        }}

        .aircraft-table td {{
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
          font-size: 12px;
        }}
        .tag {{
          display: inline-block;
          padding: 2px 6px;
          border-radius: 999px;
          background: rgba(0,216,255,0.10);
          border: 1px solid rgba(0,216,255,0.20);
          color: rgba(223,251,255,0.9);
          font-size: 11px;
          margin-right: 4px;
          margin-bottom: 3px;
          white-space: nowrap;
        }}
        .tag.mil {{
          background: rgba(255, 0, 80, 0.10);
          border-color: rgba(255, 0, 80, 0.25);
        }}
        .tag.gov {{
          background: rgba(255, 190, 0, 0.10);
          border-color: rgba(255, 190, 0, 0.25);
        }}
        .tag.cargo {{
          background: rgba(0, 255, 140, 0.10);
          border-color: rgba(0, 255, 140, 0.25);
        }}

        .muted {{
          color: rgba(255,255,255,0.65);
        }}
      </style>
    </head>
    <body>
      <header>
        <h1>Sideband Watchtower</h1>
        <div class="right">
          <a class="btn" href="/aircraft-reference/">Aircraft Reference Toolkit</a>
          <span class="pill" id="status-pill">loading…</span>
          <form method="post" action="/add-test-event" style="margin:0;">
            <button class="btn" type="submit">Add Test Event</button>
          </form>
        </div>
      </header>

      <main>
        <div class="card">
          <div class="subhead">
            <h2>Live Air Picture</h2>
            <div class="hint">Auto-refreshes every 7s • Active = heard in last 30s</div>
          </div>
          <div id="map"></div>
          <div style="height:10px;"></div>
          <table class="aircraft-table" id="aircraft-table">
            <thead>
              <tr>
                <th>HEX</th>
                <th>Callsign</th>
                <th>Role</th>
                <th>Alt</th>
                <th>Spd</th>
                <th>Age</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody id="aircraft-tbody">
              <tr><td colspan="7" class="muted">Loading aircraft…</td></tr>
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="subhead">
            <h2>Recent Events</h2>
            <div class="hint">Newest first</div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Src</th>
                <th>Chan</th>
                <th>Payload</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
      </main>

      <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
              integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
              crossorigin=""></script>

      <script>
        // --------------------------------------------------------------------
        // Basic status pill
        // --------------------------------------------------------------------
        async function refreshStatus() {{
          try {{
            const r = await fetch('/status');
            const j = await r.json();
            const total = j.total_aircraft ?? '?';
            const lastEvent = j.last_event ?? 'n/a';
            const cpu = (j.cpu_percent != null) ? (j.cpu_percent.toFixed(1) + '%') : 'n/a';
            document.getElementById('status-pill').textContent =
              `Aircraft: ${{total}} • CPU: ${{cpu}} • Last event: ${{lastEvent}}`;
          }} catch (e) {{
            document.getElementById('status-pill').textContent = 'status error';
          }}
        }}
        refreshStatus();
        setInterval(refreshStatus, 5000);

        // --------------------------------------------------------------------
        // Leaflet map setup
        // --------------------------------------------------------------------
        const receiverLat = {RECEIVER_LAT};
        const receiverLon = {RECEIVER_LON};

        const map = L.map('map').setView([receiverLat, receiverLon], 8);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
          maxZoom: 18,
          attribution: '&copy; OpenStreetMap contributors'
        }}).addTo(map);

        // Range rings (km)
        const rings = [25, 50, 100, 150];
        rings.forEach(km => {{
          L.circle([receiverLat, receiverLon], {{
            radius: km * 1000,
            color: '#00d8ff',
            weight: 1,
            opacity: 0.35,
            fillOpacity: 0
          }}).addTo(map).bindTooltip(km + ' km', {{permanent:false}});
        }});

        // Receiver marker
        L.circleMarker([receiverLat, receiverLon], {{
          radius: 6,
          color: '#00d8ff',
          fillColor: '#00d8ff',
          fillOpacity: 0.9
        }}).addTo(map).bindPopup('Receiver');

        // --------------------------------------------------------------------
        // Aircraft refresh + markers
        // --------------------------------------------------------------------
        const markers = new Map(); // hex -> Leaflet layer

        function tagClass(t) {{
          if (t === 'military') return 'tag mil';
          if (t === 'government' || t === 'law-enforcement') return 'tag gov';
          if (t === 'cargo') return 'tag cargo';
          return 'tag';
        }}

        function fmtAge(age) {{
          if (age == null) return 'n/a';
          if (age < 60) return Math.round(age) + 's';
          const m = age / 60;
          if (m < 60) return m.toFixed(1) + 'm';
          return (m/60).toFixed(1) + 'h';
        }}

        async function refreshAircraft() {{
          try {{
            const r = await fetch('/aircraft');
            const j = await r.json();
            const aircraft = j.aircraft || [];

            // Update table
            const tb = document.getElementById('aircraft-tbody');
            if (!aircraft.length) {{
              tb.innerHTML = '<tr><td colspan="7" class="muted">No aircraft with positions yet.</td></tr>';
            }} else {{
              tb.innerHTML = aircraft.map(a => {{
                const hex = a.hex || '';
                const cs = a.callsign || '';
                const role = a.role || '';
                const alt = (a.altitude != null) ? a.altitude : 'n/a';
                const spd = (a.ground_speed != null) ? a.ground_speed.toFixed(0) : 'n/a';
                const age = fmtAge(a.age_s);
                const tags = (a.tags || []).map(t => `<span class="${{tagClass(t)}}">${{t}}</span>`).join(' ');
                const link = `<a class="hex-link" href="/aircraft/${{hex}}">${{hex}}</a>`;
                const activeDot = a.active ? '🟢' : '⚫';
                return `
                  <tr>
                    <td>${{activeDot}} ${{link}}</td>
                    <td>${{cs}}</td>
                    <td>${{role}}</td>
                    <td>${{alt}}</td>
                    <td>${{spd}}</td>
                    <td>${{age}}</td>
                    <td>${{tags}}</td>
                  </tr>
                `;
              }}).join('');
            }}

            // Update map markers
            const seen = new Set();
            aircraft.forEach(a => {{
              const hex = a.hex;
              if (!hex) return;
              if (a.latitude == null || a.longitude == null) return;

              seen.add(hex);

              const label = (a.callsign || hex).trim();
              const altText = (a.altitude != null) ? (a.altitude + ' ft') : 'alt n/a';
              const age = fmtAge(a.age_s);
              const popup = `<b>${{label}}</b><br>${{altText}}<br>Age: ${{age}}`;

              const existing = markers.get(hex);
              if (existing) {{
                existing.setLatLng([a.latitude, a.longitude]);
                existing.setPopupContent(popup);
                if (a.active) {{
                  existing.setStyle({{opacity: 1.0, fillOpacity: 0.9}});
                }} else {{
                  existing.setStyle({{opacity: 0.35, fillOpacity: 0.25}});
                }}
              }} else {{
                const m = L.circleMarker([a.latitude, a.longitude], {{
                  radius: 7,
                  color: '#00d8ff',
                  fillColor: '#00d8ff',
                  fillOpacity: a.active ? 0.9 : 0.25,
                  opacity: a.active ? 1.0 : 0.35
                }}).addTo(map);
                m.bindPopup(popup);
                markers.set(hex, m);
              }}
            }});

            // Remove old markers that are no longer in the list
            for (const [hex, layer] of markers.entries()) {{
              if (!seen.has(hex)) {{
                map.removeLayer(layer);
                markers.delete(hex);
              }}
            }}

          }} catch (e) {{
            console.error('refreshAircraft error', e);
          }}
        }}

        refreshAircraft();
        setInterval(refreshAircraft, 7000);
      </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


@app.get("/aircraft/{ident}", response_class=HTMLResponse)
def aircraft_detail(ident: str) -> HTMLResponse:
    """
    Detail view for a single aircraft (by hex or callsign).
    """
    ident_clean = (ident or "").strip().upper()
    if not ident_clean:
        return HTMLResponse(content="<h1>Bad ident</h1>", status_code=400)

    # Try resolve: if it looks like hex (6 hex chars), treat as hex
    hex_code = None
    if re.fullmatch(r"[0-9A-F]{6}", ident_clean):
        hex_code = ident_clean
    else:
        # else try lookup by callsign
        conn = get_db()
        try:
            cur = conn.execute(
                "SELECT hex FROM aircraft WHERE UPPER(callsign) = ? ORDER BY last_seen DESC LIMIT 1",
                (ident_clean,),
            )
            row = cur.fetchone()
            if row:
                hex_code = row["hex"]
        finally:
            conn.close()

    if not hex_code:
        return HTMLResponse(content=f"<h1>Not found: {ident_clean}</h1>", status_code=404)

    # Ensure we have metadata
    ensure_aircraft_metadata(hex_code)

    # Grab current joined record
    summary = get_aircraft_meta_summary(hex_code)

    # If still no summary, show minimal page
    if not summary:
        return HTMLResponse(content=f"<h1>Not found: {ident_clean}</h1>", status_code=404)

    # Pull some fields
    callsign = summary.get("callsign") or ""
    last_seen = summary.get("last_seen") or ""
    altitude = summary.get("altitude")
    gs = summary.get("ground_speed")
    trk = summary.get("track")
    lat = summary.get("latitude")
    lon = summary.get("longitude")

    tags_str = summary.get("tags") or ""
    tags = [t for t in tags_str.split(",") if t] if tags_str else []
    score = summary.get("interesting_score") or 0.0

    reg = summary.get("registration") or ""
    manufacturer = summary.get("manufacturer") or ""
    model = summary.get("model") or ""
    typecode = summary.get("typecode") or ""
    operator = summary.get("operator") or ""
    country = summary.get("country") or ""
    last_lookup = summary.get("last_lookup") or ""

    # Attempt a live OpenSky pull (optional) to show enriched fields
    opensky_meta = {}
    try:
        token = icao_lookup.get_token()
        if token:
            opensky_meta = icao_lookup.get_aircraft_meta(token, hex_code) or {}
    except Exception:
        opensky_meta = {}

    # Build table rows
    def tr(label, value):
        v = "" if value is None else str(value)
        return f"<tr><th>{label}</th><td>{v}</td></tr>"

    track_rows = ""
    track_rows += tr("HEX", hex_code)
    track_rows += tr("Callsign", callsign)
    track_rows += tr("Last seen", last_seen)
    track_rows += tr("Altitude (ft)", altitude)
    track_rows += tr("Ground speed", gs)
    track_rows += tr("Track", trk)
    track_rows += tr("Latitude", lat)
    track_rows += tr("Longitude", lon)
    track_rows += tr("Tags", ", ".join(tags))
    track_rows += tr("Interesting score", f"{score:.1f}")

    meta_rows = ""
    meta_rows += tr("Registration", reg)
    meta_rows += tr("Manufacturer", manufacturer)
    meta_rows += tr("Model", model)
    meta_rows += tr("Typecode", typecode)
    meta_rows += tr("Operator", operator)
    meta_rows += tr("Country", country)
    meta_rows += tr("Last meta lookup", last_lookup)

    # Add a few OpenSky extras if present
    if opensky_meta:
        for k in ("serialNumber", "icaoAircraftClass", "owner", "built"):
            if k in opensky_meta and opensky_meta.get(k):
                meta_rows += tr(f"OpenSky {k}", opensky_meta.get(k))

    # Map JSON
    map_json = json.dumps(
        {
            "lat": lat,
            "lon": lon,
            "label": callsign or hex_code,
            "altitude": altitude,
        }
    )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Aircraft {ident_clean}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <link rel="stylesheet"
            href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
            integrity="sha256-o9N1j7kP6kGZQ8tOZcH0c2q3E8O5pQvWQY6GkGmJb9A="
            crossorigin=""/>

      <style>
        body {{
          background: #0b0f14;
          color: #f4f8ff;
          font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          margin: 0;
          padding: 14px;
        }}
        a {{
          color: #00d8ff;
          text-decoration: none;
        }}
        a:hover {{
          text-decoration: underline;
        }}
        h1 {{
          margin: 0 0 10px 0;
          font-size: 18px;
        }}
        .grid {{
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }}
        @media (max-width: 1000px) {{
          .grid {{
            grid-template-columns: 1fr;
          }}
        }}
        .card {{
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.10);
          border-radius: 14px;
          padding: 12px;
        }}
        table.detail {{
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }}
        table.detail th, table.detail td {{
          padding: 8px 8px;
          border-bottom: 1px solid rgba(255,255,255,0.08);
          text-align: left;
          vertical-align: top;
        }}
        table.detail th {{
          width: 180px;
          color: rgba(255,255,255,0.75);
          font-weight: 700;
          font-size: 12px;
        }}
        #map {{
          height: 420px;
          border-radius: 12px;
          overflow: hidden;
          border: 1px solid rgba(255,255,255,0.08);
          margin-top: 10px;
        }}
        .back-link {{
          display: inline-block;
          margin-bottom: 10px;
          font-size: 13px;
          opacity: 0.9;
        }}
        /* prevent leaflet from pulling in a white background in some cases */
        .leaflet-container {{
          background: #0b0f14 !important;
        }}

      </style>
    </head>
    <body>
      <a class="back-link" href="/">&larr; Back to dashboard</a>
      <h1>Aircraft {ident_clean}</h1>

      <div class="grid">
        <div class="card">
          <h2 style="margin-top:0;">Track / Last seen</h2>
          <table class="detail">
            {track_rows}
          </table>
        </div>

        <div class="card">
          <h2 style="margin-top:0;">Metadata</h2>
          <table class="detail">
            {meta_rows}
          </table>
        </div>
      </div>

      <div class="card">
        <h2 style="margin-top:0;">Position</h2>
        <div id="map"></div>
      </div>

      <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
              integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
              crossorigin=""></script>
      <script>
        const mapData = {map_json};

        if (mapData.lat == null || mapData.lon == null) {{
          document.getElementById('map').innerHTML =
            'No last-known position for this aircraft.';
        }} else {{
          const map = L.map('map').setView([mapData.lat, mapData.lon], 9);
          L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 18,
            attribution: '&copy; OpenStreetMap contributors'
          }}).addTo(map);

          const marker = L.circleMarker([mapData.lat, mapData.lon], {{
            radius: 7,
            color: '#00d8ff',
            fillColor: '#00d8ff',
            fillOpacity: 0.9
          }}).addTo(map);

          const altText = mapData.altitude != null ? (mapData.altitude + ' ft') : 'alt n/a';
          marker.bindPopup(String(mapData.label) + '<br>' + altText).openPopup();
        }}
      </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


@app.get("/aircraft-reference", include_in_schema=False)
@app.get("/aircraft-reference/", include_in_schema=False)
def aircraft_reference(request: Request):
    # Works whether you access Watchtower via "osint:8000" or "192.168.x.x:8000"
    host = (request.headers.get("host") or "osint").split(":")[0]
    return RedirectResponse(url=f"http://{host}/ref/", status_code=302)


# =============================================================================
#  Routes: JSON / actions
# =============================================================================
@app.post("/add-test-event")
def add_test_event():
    """
    Simple endpoint for now: create a fake event and bounce back to dashboard.
    """
    insert_test_event()
    return RedirectResponse(url="/", status_code=303)


@app.get("/health", response_class=JSONResponse)
def health() -> JSONResponse:
    """
    Very lightweight healthcheck endpoint.
    """
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    payload = {
        "status": "ok",
        "service": "sideband-watchtower",
        "host": socket.gethostname(),
        "time_utc": now,
    }
    return JSONResponse(content=payload)


@app.get("/status", response_class=JSONResponse)
def status() -> JSONResponse:
    """
    Slightly more detailed status: DB stats + basic system metrics.
    """
    info = get_basic_status()
    return JSONResponse(content=info)


@app.get("/aircraft", response_class=JSONResponse)
def aircraft_json() -> JSONResponse:
    """
    Return current aircraft with positions for the map, including freshness.
    """
    now_ts = time.time()
    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT
                a.hex,
                a.callsign,
                a.last_seen,
                a.altitude,
                a.ground_speed,
                a.track,
                a.latitude,
                a.longitude,
                a.tags,
                a.interesting_score,
                m.registration,
                m.model,
                m.typecode,
                m.operator,
                m.country
            FROM aircraft AS a
            LEFT JOIN aircraft_meta AS m
                ON m.hex = a.hex
            WHERE a.latitude IS NOT NULL AND a.longitude IS NOT NULL
            ORDER BY a.last_seen DESC
            LIMIT 200
            """
        )


        rows_out = []
        for row in cur.fetchall():
            d = dict(row)
            hex_code = d["hex"]

            # Try in-memory freshness first
            last_update = _aircraft_last_update_ts.get(hex_code)

            # Fallback: derive a timestamp from last_seen in the DB
            if last_update is None:
                last_seen_str = d.get("last_seen")
                if last_seen_str:
                    try:
                        # last_seen looks like "YYYY/MM/DD HH:MM:SS.xxx"
                        base = last_seen_str.split(".")[0]
                        dt = datetime.strptime(base, "%Y/%m/%d %H:%M:%S")
                        last_update = dt.timestamp()
                    except Exception:
                        last_update = None

            # If we *still* don't know, include it but mark as inactive
            if last_update is None:
                d["age_s"] = None
                d["active"] = False
            else:
                age_s = max(0.0, now_ts - last_update)
                d["age_s"] = age_s
                d["active"] = age_s <= 30.0  # active if heard in last 30s

            # Normalize tags + interesting_score for JSON
            tags_str = d.get("tags") or ""
            d["tags"] = [t for t in tags_str.split(",") if t] if tags_str else []
            d["interesting_score"] = d.get("interesting_score") or 0.0

            operator = d.get("operator") or ""
            model = d.get("model") or ""
            d["role"] = summarize_aircraft_role(d["tags"], operator, model)

            rows_out.append(d)

    finally:
        conn.close()

    return JSONResponse(content={"aircraft": rows_out})
