import os
import sqlite3
import socket
import asyncio
import time
import icao_lookup
import json
import re
import threading
import time

from datetime import datetime
from typing import List, Optional
from math import radians, sin, cos, sqrt, atan2
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

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

app = FastAPI()


# =============================================================================
#  SQLite DB – events + aircraft
# =============================================================================

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "watchtower.db")

def get_db() -> sqlite3.Connection:
    """
    Open a SQLite connection with Row objects so we can access columns by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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

    CREATE TABLE IF NOT EXISTS settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at TEXT
    );
    """
    conn = get_db()
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
        ensure_aircraft_extra_columns()


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



# =============================================================================
#  ADS-B / receiver config
# =============================================================================

def _get_float_env(name: str, default: float) -> float:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default

def _is_valid_lat_lon(lat: float, lon: float) -> bool:
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0

def _get_settings_receiver_coords() -> Optional[tuple[float, float]]:
    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT key, value
            FROM settings
            WHERE key IN ('receiver_lat', 'receiver_lon')
            """
        )
        rows = {row["key"]: row["value"] for row in cur.fetchall()}
    finally:
        conn.close()

    lat_raw = (rows.get("receiver_lat") or "").strip()
    lon_raw = (rows.get("receiver_lon") or "").strip()
    if not lat_raw or not lon_raw:
        return None

    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except ValueError:
        return None

    if not _is_valid_lat_lon(lat, lon):
        return None
    return lat, lon

def save_receiver_coords(lat: float, lon: float) -> None:
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES ('receiver_lat', ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (str(lat), now),
        )
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES ('receiver_lon', ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (str(lon), now),
        )
        conn.commit()
    finally:
        conn.close()

def resolve_receiver_config() -> tuple[float, float, str, bool]:
    env_lat_raw = (os.getenv("RECEIVER_LAT", "") or "").strip()
    env_lon_raw = (os.getenv("RECEIVER_LON", "") or "").strip()
    if env_lat_raw and env_lon_raw:
        try:
            env_lat = float(env_lat_raw)
            env_lon = float(env_lon_raw)
            if _is_valid_lat_lon(env_lat, env_lon):
                return env_lat, env_lon, "env", True
        except ValueError:
            pass

    setup_coords = _get_settings_receiver_coords()
    if setup_coords is not None:
        return setup_coords[0], setup_coords[1], "setup", True

    return 0.0, 0.0, "placeholder", False

def apply_receiver_config(lat: float, lon: float, source: str, configured: bool) -> None:
    global RECEIVER_LAT, RECEIVER_LON, RECEIVER_CONFIG_SOURCE, RECEIVER_COORDS_CONFIGURED
    RECEIVER_LAT = lat
    RECEIVER_LON = lon
    RECEIVER_CONFIG_SOURCE = source
    RECEIVER_COORDS_CONFIGURED = configured

ADS_B_HOST = os.getenv("ADSB_HOST", "127.0.0.1")
try:
    ADS_B_PORT = int(os.getenv("ADSB_PORT", "30003"))
except ValueError:
    ADS_B_PORT = 30003
AIRCRAFT_EVENT_MIN_INTERVAL = 60.0  # seconds between "contact" events per hex

RECEIVER_LAT = _get_float_env("RECEIVER_LAT", 0.0)
RECEIVER_LON = _get_float_env("RECEIVER_LON", 0.0)
RECEIVER_COORDS_CONFIGURED = bool(
    (os.getenv("RECEIVER_LAT", "") or "").strip()
    and (os.getenv("RECEIVER_LON", "") or "").strip()
)
RECEIVER_CONFIG_SOURCE = "env" if RECEIVER_COORDS_CONFIGURED else "placeholder"

# Dicts for throttling + behavior detection + freshness
_last_aircraft_event_ts: dict[str, float] = {}
_recent_positions: dict[str, list[tuple[float, float, float]]] = {}
_last_loiter_event_ts: dict[str, float] = {}
_last_rapid_vs_event_ts: dict[str, float] = {}
_aircraft_last_alt: dict[str, tuple[Optional[int], float]] = {}
_aircraft_last_update_ts: dict[str, float] = {}  # for "active" vs "stale"


# =============================================================================
#  Helpers – distance, events, status
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


def summarize_aircraft_role(tags: list[str], operator: str, model: str) -> str:
    tset = set(tag.lower() for tag in tags)
    op = operator.upper()
    mdl = model.upper()

    # Medevac heuristics (you can tune this for local operators)
    if any(k in op for k in ("LIFE", "MED", "STAT", "EVAC", "AEROMED", "HEMS")):
        if "helicopter" in tset:
            return "Medevac helicopter"
        return "Medevac aircraft"

    if "law-enforcement" in tset:
        if "helicopter" in tset:
            return "Law-enforcement helicopter"
        return "Law-enforcement aircraft"

    if "military" in tset and "cargo" in tset:
        return "Military cargo"

    if "military" in tset:
        if "helicopter" in tset:
            return "Military helicopter"
        return "Military aircraft"

    if "government" in tset:
        return "Government aircraft"

    if "cargo" in tset:
        return "Cargo freighter"

    if "bizjet" in tset:
        return "Business jet"

    if "helicopter" in tset:
        return "Helicopter"

    # Generic airline/GA traffic
    if "airline-or-ga" in tset:
        # If it looks like a big tube
        if any(k in mdl for k in ("AIRBUS", "BOEING", "ERJ", "CRJ", "E17", "E19", "E75")):
            return "Passenger jet"
        return "Light aircraft"

    if "unknown" in tset:
        return "Unknown aircraft"

    return "Aircraft"



def update_aircraft_tags_and_score(hex_ident: str) -> None:
    """
    Recompute tags + interesting_score for a single hex based on
    current aircraft + aircraft_meta data.
    """
    hex_ident = (hex_ident or "").upper().strip()
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
        tags_str = ",".join(tags) if tags else None

        conn.execute(
            """
            UPDATE aircraft
            SET tags = ?, interesting_score = ?
            WHERE hex = ?
            """,
            (tags_str, score, hex_ident),
        )
        conn.commit()
    finally:
        conn.close()





def get_aircraft_meta_summary(hex_ident: str) -> Optional[str]:
    """
    Return a short human-readable summary string for an aircraft,
    e.g. "767-300F · N296FE · Federal Express · United States"
    or None if we have no metadata.
    """
    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT registration, model, operator, country
            FROM aircraft_meta
            WHERE hex = ?
            """,
            (hex_ident,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    parts = []
    if row["model"]:
        parts.append(row["model"])
    if row["registration"]:
        parts.append(row["registration"])
    if row["operator"]:
        parts.append(row["operator"])
    if row["country"]:
        parts.append(row["country"])

    return " · ".join(parts) if parts else None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-circle distance between two lat/lon points in kilometers.
    """
    R = 6371.0
    phi1 = radians(lat1)
    phi2 = radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)

    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


def fetch_recent_events(limit: int = 50) -> List[sqlite3.Row]:
    conn = get_db()
    try:
        cur = conn.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cur.fetchall()
    finally:
        conn.close()
def extract_adsb_ident_from_payload(payload: Optional[str]) -> Optional[str]:
    """
    For payloads like 'ADS-B contact A30C46 at 14475 ft' or
    'ADS-B contact DAL123', return 'A30C46' or 'DAL123'.
    """
    if not payload:
        return None
    text = " ".join(str(payload).split()).upper()
    m = re.search(r"ADS-B CONTACT\s+([A-Z0-9]+)", text)
    if not m:
        return None
    return m.group(1)


def insert_test_event() -> None:
    """
    Insert a fake event so we can see the dashboard change.
    """
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sample = {
        "timestamp": now,
        "source": "test-generator",
        "channel": "lab",
        "latitude": 40.0,
        "longitude": -75.0,
        "payload": "This is a synthetic test event from osint.",
        "severity": "info",
    }

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO events
            (timestamp, source, channel, latitude, longitude, payload, severity)
            VALUES (:timestamp, :source, :channel, :latitude, :longitude,
                    :payload, :severity)
            """,
            sample,
        )
        conn.commit()
    finally:
        conn.close()


def get_basic_status() -> dict:
    """
    Gather simple service + host status info for /status.
    """
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    conn = get_db()
    try:
        # Events
        cur = conn.execute("SELECT COUNT(*) AS c FROM events")
        total_events = cur.fetchone()["c"]

        cur = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT 1"
        )
        last = cur.fetchone()

        # Aircraft
        cur = conn.execute("SELECT COUNT(*) AS c FROM aircraft")
        total_aircraft = cur.fetchone()["c"]
    finally:
        conn.close()

    last_event: Optional[dict] = None
    if last:
        last_event = {
            "id": last["id"],
            "timestamp": last["timestamp"],
            "source": last["source"],
            "channel": last["channel"],
            "severity": last["severity"],
        }

    # System stats (if psutil is available)
    cpu_pct: Optional[float] = None
    mem_info: Optional[dict] = None
    disk_info: Optional[dict] = None

    if psutil is not None:
        cpu_pct = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        mem_info = {
            "total_mb": round(mem.total / (1024 * 1024)),
            "used_mb": round(mem.used / (1024 * 1024)),
            "percent": mem.percent,
        }
        disk_info = {
            "total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
            "used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
            "percent": disk.percent,
        }

    return {
        "service": "sideband-watchtower",
        "host": socket.gethostname(),
        "time_utc": now,
        "receiver_config_source": RECEIVER_CONFIG_SOURCE,
        "receiver_configured": RECEIVER_COORDS_CONFIGURED,
        "receiver_lat": RECEIVER_LAT,
        "receiver_lon": RECEIVER_LON,
        "total_events": total_events,
        "total_aircraft": total_aircraft,
        "last_event": last_event,
        "cpu_percent": cpu_pct,
        "memory": mem_info,
        "disk_root": disk_info,
    }


# =============================================================================
#  Aircraft helpers + ADS-B ingestion
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

    ensure_aircraft_metadata(hex_ident)



    # classify and score this aircraft based on metadata
    update_aircraft_tags_and_score(hex_ident)



def maybe_insert_aircraft_contact_event(
    hex_ident: str,
    callsign: Optional[str],
    ts_str: str,
    latitude: float,
    longitude: float,
    altitude: Optional[int],
) -> None:
    """
    Basic "contact" event – throttled so we don't spam per aircraft.
    """
    now_ts = time.time()
    last_ts = _last_aircraft_event_ts.get(hex_ident)
    if last_ts is not None and (now_ts - last_ts) < AIRCRAFT_EVENT_MIN_INTERVAL:
        return

    _last_aircraft_event_ts[hex_ident] = now_ts

    label = callsign or hex_ident

    meta_summary = get_aircraft_meta_summary(hex_ident)

    if altitude is not None:
        if meta_summary:
            payload = f"ADS-B contact {label} ({meta_summary}) at {altitude} ft"
        else:
            payload = f"ADS-B contact {label} at {altitude} ft"
    else:
        if meta_summary:
            payload = f"ADS-B contact {label} ({meta_summary})"
        else:
            payload = f"ADS-B contact {label}"


    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO events
            (timestamp, source, channel, latitude, longitude, payload, severity)
            VALUES (?, 'adsb', '1090MHz', ?, ?, ?, 'info')
            """,
            (ts_str, latitude, longitude, payload),
        )
        conn.commit()
    finally:
        conn.close()


def update_behavior_events(
    hex_ident: str,
    callsign: Optional[str],
    ts_str: str,
    lat: float,
    lon: float,
    altitude: Optional[int],
) -> None:
    """
    Higher-level behavior detection:
      - Loitering / holding pattern
      - Rapid climb / descent
    Generates additional events with channels 'pattern' and 'vertical'.
    """
    label = callsign or hex_ident
    now_ts = time.time()

    # --- Track positions for loiter detection ---
    pts = _recent_positions.get(hex_ident, [])
    pts.append((lat, lon, now_ts))
    if len(pts) > 60:
        pts = pts[-60:]
    _recent_positions[hex_ident] = pts

    # Loiter detection: many points staying within a small radius for several minutes
    loiter_radius_km = 5.0
    loiter_min_points = 12
    loiter_min_duration = 5 * 60  # seconds
    if len(pts) >= loiter_min_points:
        lat_avg = sum(p[0] for p in pts) / len(pts)
        lon_avg = sum(p[1] for p in pts) / len(pts)
        max_dist = max(haversine_km(lat_avg, lon_avg, p[0], p[1]) for p in pts)
        duration = pts[-1][2] - pts[0][2]

        last_loiter_ts = _last_loiter_event_ts.get(hex_ident, 0.0)
        if (
            max_dist <= loiter_radius_km
            and duration >= loiter_min_duration
            and (now_ts - last_loiter_ts) >= 600.0  # 10 min cooldown
        ):
            _last_loiter_event_ts[hex_ident] = now_ts
            minutes = int(duration / 60)
            payload = (
                f"ADS-B: {label} loitering within ~{loiter_radius_km:.1f} km "
                f"for ~{minutes} min"
            )
            conn = get_db()
            try:
                conn.execute(
                    """
                    INSERT INTO events
                    (timestamp, source, channel, latitude, longitude, payload, severity)
                    VALUES (?, 'adsb', 'pattern', ?, ?, ?, 'info')
                    """,
                    (ts_str, lat_avg, lon_avg, payload),
                )
                conn.commit()
            finally:
                conn.close()

    # --- Rapid climb / descent detection (vertical speed) ---
    if altitude is not None:
        last_alt, last_time = _aircraft_last_alt.get(hex_ident, (None, None))
        if last_alt is not None and last_time is not None:
            dt = now_ts - last_time
            if dt > 5.0:
                rate_fpm = (altitude - last_alt) / (dt / 60.0)
                vs_threshold = 2000.0  # ft/min
                if abs(rate_fpm) >= vs_threshold:
                    last_vs_ts = _last_rapid_vs_event_ts.get(hex_ident, 0.0)
                    if (now_ts - last_vs_ts) >= 300.0:  # 5 min cooldown
                        _last_rapid_vs_event_ts[hex_ident] = now_ts
                        direction = "climb" if rate_fpm > 0 else "descent"
                        payload = (
                            f"ADS-B: rapid {direction} by {label}: "
                            f"{int(rate_fpm)} fpm"
                        )
                        conn = get_db()
                        try:
                            conn.execute(
                                """
                                INSERT INTO events
                                (timestamp, source, channel, latitude, longitude, payload, severity)
                                VALUES (?, 'adsb', 'vertical', ?, ?, ?, 'info')
                                """,
                                (ts_str, lat, lon, payload),
                            )
                            conn.commit()
                        finally:
                            conn.close()

        _aircraft_last_alt[hex_ident] = (altitude, now_ts)


def process_sbs1_line(line: str) -> None:
    """
    Parse a single SBS-1 / BaseStation-style line from dump1090-fa
    and update aircraft + optional event.
    """
    parts = line.split(",")
    if len(parts) < 22:
        return
    if parts[0] != "MSG":
        return

    transmission_type = parts[1]
    try:
        transmission_type = int(transmission_type)
    except ValueError:
        return

    hex_ident = parts[4].strip().upper()
    if not hex_ident:
        return

    callsign = parts[10].strip() or None

    # Use generated date/time fields if available
    date_str = parts[6].strip() or parts[8].strip()
    time_str = parts[7].strip() or parts[9].strip()
    if date_str and time_str:
        ts_str = f"{date_str} {time_str}"
    else:
        ts_str = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    alt = None
    gs = None
    track = None
    lat = None
    lon = None

    if parts[11].strip():
        try:
            alt = int(float(parts[11]))
        except ValueError:
            pass

    if parts[12].strip():
        try:
            gs = float(parts[12])
        except ValueError:
            pass

    if parts[13].strip():
        try:
            track = float(parts[13])
        except ValueError:
            pass

    if parts[14].strip() and parts[15].strip():
        try:
            lat = float(parts[14])
            lon = float(parts[15])
        except ValueError:
            lat = None
            lon = None

    # Only create/update position if we have lat/lon
    if lat is None or lon is None:
        return

    # mark last update time for freshness
    _aircraft_last_update_ts[hex_ident] = time.time()

    # Look up static metadata (registration, model, operator, etc.)
    # Only does an API call the first time we see this hex.
    ensure_aircraft_metadata(hex_ident)

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



@app.on_event("startup")
async def startup_event():
    init_db()
    lat, lon, source, configured = resolve_receiver_config()
    apply_receiver_config(lat, lon, source, configured)
    print(f"[Startup] ADS-B feed target: {ADS_B_HOST}:{ADS_B_PORT}", flush=True)
    print(f"[Startup] Receiver config source: {RECEIVER_CONFIG_SOURCE}", flush=True)
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
#  Routes – HTML dashboard + JSON endpoints
# =============================================================================

@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    if not RECEIVER_COORDS_CONFIGURED:
        return RedirectResponse(url="/setup", status_code=303)

    events = fetch_recent_events(limit=100)

    rows_html = ""
    for ev in events:
        severity = (ev["severity"] or "").lower()
        if severity == "critical":
            sev_class = "sev-critical"
        elif severity in ("warn", "warning"):
            sev_class = "sev-warn"
        elif severity == "info":
            sev_class = "sev-info"
        else:
            sev_class = "sev-other"

        payload = ev["payload"] or ""
        payload_short = payload[:120]

        ident = None
        if (ev["source"] or "").lower() == "adsb":
            ident = extract_adsb_ident_from_payload(payload)

        if ident:
            # make payload clickable → /aircraft/<ident>
            payload_cell_html = f'<a href="/aircraft/{ident}">{payload_short}</a>'
        else:
            payload_cell_html = payload_short

        rows_html += f"""
        <tr class="{sev_class}">
          <td>{ev['timestamp']}</td>
          <td>{ev['source']}</td>
          <td>{ev['channel'] or ''}</td>
          <td>{ev['latitude'] or ''}</td>
          <td>{ev['longitude'] or ''}</td>
          <td>{payload_cell_html}</td>
          <td>{ev['severity'] or ''}</td>
        </tr>
        """


    if not rows_html:
        rows_html = (
            '<tr><td colspan="7">'
            'No events yet. Use "Inject test event" or wait for ADS-B contacts.'
            "</td></tr>"
        )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <title>Sideband Watchtower – osint</title>
      <link rel="stylesheet"
            href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
            integrity="sha256-p4NxAoJBhI0C2f2RTGPaMhF0zYK38nYuyj8vPqn+1po="
            crossorigin=""/>
      <style>
        body {{
          background: #050712;
          color: #e4e9ff;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0;
          padding: 0;
        }}
        header {{
          background: linear-gradient(90deg, #ff6a00, #ffb300, #00e0ff);
          padding: 12px 20px;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          font-size: 14px;
        }}
        header span.brand {{
          display: inline-block;
          padding: 2px 8px;
          border-radius: 999px;
          background: rgba(0,0,0,0.3);
          margin-right: 8px;
        }}
        header span.meta {{
          font-weight: 400;
          font-size: 11px;
          margin-left: 10px;
        }}
        main {{
          padding: 16px 20px 40px 20px;
        }}
        .status-bar {{
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          padding: 8px 10px;
          margin: 8px 0 10px 0;
          background: rgba(10,14,40,0.9);
          border-radius: 8px;
          border: 1px solid rgba(0,224,255,0.35);
          box-shadow: 0 0 12px rgba(0,224,255,0.25);
        }}
        .status-item {{
          font-size: 11px;
          color: #c3ccff;
          white-space: nowrap;
        }}
        .status-label {{
          text-transform: uppercase;
          letter-spacing: 0.12em;
          font-size: 10px;
          color: #7b84b5;
          margin-right: 4px;
        }}
        .filter-bar {{
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          align-items: center;
          margin: 8px 0 10px 0;
          font-size: 11px;
          color: #c3ccff;
        }}
        .filter-bar label {{
          display: flex;
          align-items: center;
          gap: 4px;
        }}
        .filter-bar select {{
          background: #050712;
          color: #e4e9ff;
          border-radius: 999px;
          border: 1px solid rgba(0,224,255,0.4);
          font-size: 11px;
          padding: 2px 8px;
        }}
        .controls {{
          display: flex;
          gap: 12px;
          align-items: center;
          margin-bottom: 10px;
          flex-wrap: wrap;
        }}
        .controls form {{
          margin: 0;
        }}
        button {{
          background: #ff6a00;
          border: none;
          border-radius: 999px;
          padding: 6px 14px;
          color: white;
          font-weight: 600;
          cursor: pointer;
          font-size: 13px;
        }}
        button:hover {{
          filter: brightness(1.15);
        }}
        a.btn {{
          display: inline-block;
          background: #ff6a00;
          border: none;
          border-radius: 999px;
          padding: 6px 14px;
          color: white;
          font-weight: 600;
          cursor: pointer;
          font-size: 13px;
          text-decoration: none;
          }}
         a.btn:hover {{
          filter: brightness(1.15);
         }}
        #map {{
          width: 100%;
          height: 360px;
          border-radius: 8px;
          border: 1px solid rgba(0,224,255,0.35);
          margin-bottom: 10px;
          box-shadow: 0 0 12px rgba(0,224,255,0.25);
          overflow: hidden;
          position: relative;
        }}
        .leaflet-container {{
          width: 100%;
          height: 100%;
          position: relative;
          overflow: hidden;
        }}
        .leaflet-tile {{
          position: absolute !important;
          width: 256px !important;
          height: 256px !important;
          max-width: none !important;
          box-sizing: content-box !important;
          border: none !important;
          padding: 0 !important;
          margin: 0 !important;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
          margin-top: 8px;
        }}
        th, td {{
          border-bottom: 1px solid rgba(255,255,255,0.06);
          padding: 4px 6px;
          text-align: left;
          vertical-align: top;
        }}
        th {{
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: #9aa2d0;
        }}
        tr:hover {{
          background: rgba(255,255,255,0.03);
        }}
        .meta {{
          font-size: 11px;
          color: #8b93c9;
        }}
      </style>
    </head>
    <body>
      <header>
        <span class="brand">Grey Cell Works</span>
        <span>Sideband Watchtower</span>
        <span class="meta">live ADS-B traffic</span>
      </header>
      <main>
        <div class="status-bar">
          <div class="status-item">
            <span class="status-label">Host</span>
            <span id="status-host">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">Events</span>
            <span id="status-events">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">AC</span>
            <span id="status-ac">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">CPU</span>
            <span id="status-cpu">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">Mem</span>
            <span id="status-mem">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">Disk</span>
            <span id="status-disk">–</span>
          </div>
          <div class="status-item">
            <span class="status-label">Updated</span>
            <span id="status-updated">–</span>
          </div>
        </div>

        <div class="filter-bar">
          <label>
            Alt &le;
            <select id="filter-alt">
              <option value="">Any</option>
              <option value="5000">5k ft</option>
              <option value="10000">10k ft</option>
              <option value="15000">15k ft</option>
              <option value="25000">25k ft</option>
            </select>
          </label>
          <label>
            Range &le;
            <select id="filter-range">
              <option value="">Any</option>
              <option value="25">25 NM</option>
              <option value="50">50 NM</option>
              <option value="100">100 NM</option>
            </select>
          </label>
        </div>

        <div id="map"></div>

        <div class="controls">
          <form method="post" action="/add-test-event">
            <button type="submit">Inject test event</button>
          </form>

           <a class="btn" href="/aircraft-reference/" target="_blank" rel="noopener">
            Aircraft Reference
           </a>
        </div>

        <!-- One row per aircraft table -->
        <table>
          <thead>
            <tr>
              <th>Last seen (UTC)</th>
              <th>Ident</th>
              <th>Role</th>
              <th>Altitude</th>
              <th>Range</th>
              <th>Operator / Model</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody id="aircraft-body">
            <tr><td colspan="7">Loading aircraft...</td></tr>
          </tbody>
        </table>
      </main>


      <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
              integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
              crossorigin=""></script>
      <script>
      const RX_LAT = {RECEIVER_LAT};
      const RX_LON = {RECEIVER_LON};
      const RANGE_RINGS_NM = [25, 50, 100];

      let map;
      let rangeRings = [];
      let aircraftMarkers = {{}};
      let aircraftTracks = {{}};
      let aircraftTrackPoints = {{}};

      function initMap() {{
        map = L.map('map').setView([RX_LAT, RX_LON], 8);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
          maxZoom: 18,
          attribution: '&copy; OpenStreetMap contributors'
        }}).addTo(map);

        // Range rings around receiver
        RANGE_RINGS_NM.forEach(nm => {{
          const ring = L.circle([RX_LAT, RX_LON], {{
            radius: nm * 1852,
            color: '#5555ff',
            weight: 1,
            opacity: 0.5,
            fillOpacity: 0
          }});
          ring.addTo(map);
          rangeRings.push(ring);
        }});

        // Receiver marker
        L.circleMarker([RX_LAT, RX_LON], {{
          radius: 5,
          color: '#ffffff',
          fillColor: '#ffffff',
          fillOpacity: 1.0
        }}).addTo(map)
          .bindPopup('Receiver');
      }}

      function colorForAltitude(alt) {{
        if (alt == null) {{
          return '#cccccc';
        }}
        if (alt < 5000) {{
          return '#ff4136';        // low
        }} else if (alt < 15000) {{
          return '#ff851b';        // medium
        }} else if (alt < 30000) {{
          return '#2ecc40';        // high
        }} else {{
          return '#0074d9';        // very high
        }}
      }}

      function haversineNm(lat1, lon1, lat2, lon2) {{
        const R = 3440.065; // Earth radius in NM
        const toRad = Math.PI / 180;
        const dLat = (lat2 - lat1) * toRad;
        const dLon = (lon2 - lon1) * toRad;
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(lat1*toRad) * Math.cos(lat2*toRad) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
      }}

      async function refreshStatus() {{
        try {{
          const resp = await fetch('/status');
          if (!resp.ok) throw new Error('status HTTP ' + resp.status);
          const data = await resp.json();

          const hostEl = document.getElementById('status-host');
          const eventsEl = document.getElementById('status-events');
          const acEl = document.getElementById('status-ac');
          const cpuEl = document.getElementById('status-cpu');
          const memEl = document.getElementById('status-mem');
          const diskEl = document.getElementById('status-disk');
          const updatedEl = document.getElementById('status-updated');

          if (hostEl) hostEl.textContent = data.host || '?';
          if (eventsEl) eventsEl.textContent = (data.total_events ?? '?');
          if (acEl) acEl.textContent = (data.total_aircraft ?? '?');

          if (cpuEl) {{
            if (data.cpu_percent != null) {{
              cpuEl.textContent = data.cpu_percent.toFixed(1) + '%';
            }} else {{
              cpuEl.textContent = 'n/a';
            }}
          }}

          if (memEl) {{
            if (data.memory) {{
              memEl.textContent =
                data.memory.used_mb + '/' + data.memory.total_mb +
                ' MB (' + data.memory.percent + '%)';
            }} else {{
              memEl.textContent = 'n/a';
            }}
          }}

          if (diskEl) {{
            if (data.disk_root) {{
              diskEl.textContent =
                data.disk_root.used_gb + '/' + data.disk_root.total_gb +
                ' GB (' + data.disk_root.percent + '%)';
            }} else {{
              diskEl.textContent = 'n/a';
            }}
          }}

          if (updatedEl) {{
            updatedEl.textContent = data.time_utc || '';
          }}
        }} catch (err) {{
          const updatedEl = document.getElementById('status-updated');
          if (updatedEl) {{
            updatedEl.textContent = 'error';
          }}
        }}
      }}

      async function refreshAircraft() {{
        try {{
          const resp = await fetch('/aircraft');
          if (!resp.ok) throw new Error('aircraft HTTP ' + resp.status);
          const data = await resp.json();
          const list = data.aircraft || [];
          const seen = new Set();

          const altSel = document.getElementById('filter-alt');
          const rangeSel = document.getElementById('filter-range');
          const maxAlt = altSel && altSel.value ? parseInt(altSel.value, 10) : null;
          const maxRangeNm = rangeSel && rangeSel.value ? parseFloat(rangeSel.value) : null;

          const tbody = document.getElementById('aircraft-body');
          if (tbody) {{
            tbody.innerHTML = '';
          }}

          for (const ac of list) {{
            if (ac.latitude == null || ac.longitude == null) continue;

            const age = ac.age_s != null ? ac.age_s : 0;
            const active = ac.active === true;

            // Distance from receiver in NM (used for filter + table)
            let dNm = null;
            try {{
              dNm = haversineNm(RX_LAT, RX_LON, ac.latitude, ac.longitude);
            }} catch (_) {{
              dNm = null;
            }}

            // Filters
            if (maxAlt !== null && ac.altitude != null && ac.altitude > maxAlt) {{
              continue;
            }}
            if (maxRangeNm !== null && dNm !== null && dNm > maxRangeNm) {{
              continue;
            }}

            const hex = ac.hex;
            seen.add(hex);
            const latlng = [ac.latitude, ac.longitude];

            const label = (ac.callsign || ac.hex || '???');
            const altText = ac.altitude ? (ac.altitude + ' ft') : 'alt n/a';
            const ageText = age.toFixed(0) + 's old';

            const metaParts = [];
            if (ac.registration) metaParts.push(ac.registration);
            if (ac.model) metaParts.push(ac.model);
            if (ac.operator) metaParts.push(ac.operator);
            if (ac.country) metaParts.push(ac.country);
            const metaText = metaParts.length ? metaParts.join(' · ') : null;

            let popup = label + '<br>' + altText + '<br>' + ageText;
            if (metaText) {{
              popup += '<br>' + metaText;
            }}

            const baseColor = colorForAltitude(ac.altitude);
            let markerColor = baseColor;
            let strokeColor = '#ffffff';
            let radius = 6;
            let opacity = 0.95;

            if (!active) {{
              markerColor = '#555555';
              strokeColor = '#999999';
              radius = 5;
              opacity = 0.6;
            }}

            // --- Marker (moving dot) ---
            let marker = aircraftMarkers[hex];
            if (!marker) {{
              marker = L.circleMarker(latlng, {{
                radius: radius,
                color: strokeColor,
                weight: 1,
                fillColor: markerColor,
                fillOpacity: opacity
              }});
              marker.bindPopup(popup);
              marker.addTo(map);
              aircraftMarkers[hex] = marker;
            }} else {{
              marker.setLatLng(latlng);
              marker.setStyle({{
                radius: radius,
                color: strokeColor,
                fillColor: markerColor,
                fillOpacity: opacity
              }});
              marker.setPopupContent(popup);
            }}

            // --- Track (polyline trail) ---
            let pts = aircraftTrackPoints[hex] || [];
            const last = pts.length ? pts[pts.length - 1] : null;
            if (!last || last[0] !== latlng[0] || last[1] !== latlng[1]) {{
              pts.push(latlng);
              if (pts.length > 300) {{
                pts.shift();
              }}
              aircraftTrackPoints[hex] = pts;

              let track = aircraftTracks[hex];
              if (!track) {{
                track = L.polyline(pts, {{
                  weight: 3,
                  opacity: 0.8,
                  color: baseColor,
                  dashArray: active ? null : '4 4'
                }});
                track.addTo(map);
                aircraftTracks[hex] = track;
              }} else {{
                track.setLatLngs(pts);
                track.setStyle({{
                  color: baseColor,
                  opacity: active ? 0.8 : 0.4,
                  dashArray: active ? null : '4 4'
                }});
              }}
            }}

            // --- Table row (one row per aircraft) ---
            if (tbody) {{
              const identLabel = ac.callsign ? `${{ac.callsign}} ({{ac.hex}})` : (ac.hex || '');
              const detailUrl = ac.hex ? `/aircraft/${{encodeURIComponent(ac.hex)}}` : '#';

              const role = ac.role || '';
              const altShort = ac.altitude != null ? (ac.altitude + ' ft') : '';
              const rangeText = dNm != null ? dNm.toFixed(1) + ' nm' : '';
              const opModelParts = [];
              if (ac.operator) opModelParts.push(ac.operator);
              if (ac.model) opModelParts.push(ac.model);
              const opModel = opModelParts.join(' · ');
              const scoreText = (ac.interesting_score != null)
                  ? ac.interesting_score.toFixed(0)
                  : '';

              const lastSeen = ac.last_seen || '';

              tbody.insertAdjacentHTML('beforeend', `
                <tr>
                  <td>${{lastSeen}}</td>
                  <td><a href="${{detailUrl}}">${{identLabel}}</a></td>
                  <td>${{role}}</td>
                  <td>${{altShort}}</td>
                  <td>${{rangeText}}</td>
                  <td>${{opModel}}</td>
                  <td>${{scoreText}}</td>
                </tr>
              `);
            }}
          }}

          // Remove markers/tracks for aircraft that disappeared from the DB
          for (const hex in aircraftMarkers) {{
            if (!seen.has(hex)) {{
              map.removeLayer(aircraftMarkers[hex]);
              delete aircraftMarkers[hex];
            }}
          }}
          for (const hex in aircraftTracks) {{
            if (!seen.has(hex)) {{
              map.removeLayer(aircraftTracks[hex]);
              delete aircraftTracks[hex];
              delete aircraftTrackPoints[hex];
            }}
          }}
        }} catch (err) {{
          // ignore for now
        }}
      }}


      document.addEventListener('DOMContentLoaded', function() {{
        initMap();
        refreshStatus();
        refreshAircraft();
        setInterval(refreshStatus, 5000);
        setInterval(refreshAircraft, 7000);
      }});
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

def render_setup_page(error: Optional[str] = None, lat_value: str = "", lon_value: str = "") -> HTMLResponse:
    error_html = f'<p style="color:#ff8f8f;">{error}</p>' if error else ""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Receiver Setup - Sideband Watchtower</title>
      <style>
        body {{
          background: #070b16;
          color: #e8edff;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0;
          padding: 30px 16px;
        }}
        .card {{
          max-width: 640px;
          margin: 0 auto;
          background: #0d1529;
          border: 1px solid rgba(0,224,255,0.2);
          border-radius: 12px;
          padding: 18px;
        }}
        h1 {{
          margin-top: 0;
        }}
        label {{
          display: block;
          margin-top: 12px;
          margin-bottom: 6px;
          color: #b8c9ff;
        }}
        input {{
          width: 100%;
          padding: 10px;
          border-radius: 8px;
          border: 1px solid rgba(0,224,255,0.3);
          background: #080f21;
          color: #f2f6ff;
          box-sizing: border-box;
        }}
        button {{
          margin-top: 16px;
          padding: 10px 14px;
          border: 1px solid rgba(0,224,255,0.35);
          border-radius: 8px;
          background: rgba(0,216,255,0.12);
          color: #e6faff;
          cursor: pointer;
          font-weight: 600;
        }}
        .note {{
          margin-top: 14px;
          color: #9fb2ea;
          font-size: 14px;
        }}
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Receiver setup</h1>
        <p>Enter your local ADS-B receiver coordinates. These values are stored locally in SQLite on this device.</p>
        <p class="note">Do not commit private receiver coordinates to source control. Keep private values in local runtime config only.</p>
        <p class="note">Example format: latitude <code>40.12345</code>, longitude <code>-75.12345</code></p>
        {error_html}
        <form method="post" action="/setup">
          <label for="latitude">Latitude (-90 to 90)</label>
          <input id="latitude" name="latitude" value="{lat_value}" required />
          <label for="longitude">Longitude (-180 to 180)</label>
          <input id="longitude" name="longitude" value="{lon_value}" required />
          <button type="submit">Save receiver location</button>
        </form>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/setup", response_class=HTMLResponse)
def setup_get() -> HTMLResponse:
    if RECEIVER_COORDS_CONFIGURED:
        return RedirectResponse(url="/", status_code=303)

    db_coords = _get_settings_receiver_coords()
    if db_coords is None:
        return render_setup_page()
    return render_setup_page(lat_value=f"{db_coords[0]}", lon_value=f"{db_coords[1]}")

@app.post("/setup", response_class=HTMLResponse)
def setup_post(latitude: str = Form(...), longitude: str = Form(...)):
    lat_raw = (latitude or "").strip()
    lon_raw = (longitude or "").strip()

    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except ValueError:
        return render_setup_page(
            error="Latitude and longitude must be numeric values.",
            lat_value=lat_raw,
            lon_value=lon_raw,
        )

    if not _is_valid_lat_lon(lat, lon):
        return render_setup_page(
            error="Latitude must be between -90 and 90, and longitude between -180 and 180.",
            lat_value=lat_raw,
            lon_value=lon_raw,
        )

    save_receiver_coords(lat, lon)
    new_lat, new_lon, new_source, new_configured = resolve_receiver_config()
    apply_receiver_config(new_lat, new_lon, new_source, new_configured)
    return RedirectResponse(url="/", status_code=303)


@app.get("/aircraft/{ident}", response_class=HTMLResponse)
def aircraft_detail(ident: str) -> HTMLResponse:
    ident_clean = (ident or "").strip().upper()

    # Look up last-known track from local aircraft table
    conn = get_db()
    try:
        # try by hex first
        cur = conn.execute(
            """
            SELECT hex, callsign, last_seen, altitude, ground_speed,
                   track, latitude, longitude
            FROM aircraft
            WHERE hex = ?
            """,
            (ident_clean,),
        )
        row = cur.fetchone()

        if row is None:
            # fall back to callsign
            cur = conn.execute(
                """
                SELECT hex, callsign, last_seen, altitude, ground_speed,
                       track, latitude, longitude
                FROM aircraft
                WHERE callsign = ?
                ORDER BY last_seen DESC
                LIMIT 1
                """,
                (ident_clean,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    ac = dict(row) if row is not None else None
    hex_code = ac.get("hex") if ac else None

    # Pull static metadata from OpenSky via icao_lookup
    meta = None
    meta_error = None
    if hex_code:
        try:
            token = icao_lookup.get_token()
            meta = icao_lookup.get_aircraft_meta(token, hex_code)
        except Exception as exc:
            meta_error = str(exc)

    def td(label: str, value: Optional[str]) -> str:
        if value is None or value == "":
            return ""
        return f"<tr><th>{label}</th><td>{value}</td></tr>"

    # Track / last-seen info
    if ac:
        track_rows = ""
        track_rows += td("Hex", ac.get("hex"))
        track_rows += td("Callsign", ac.get("callsign"))
        track_rows += td("Last seen (UTC)", ac.get("last_seen"))

        alt = ac.get("altitude")
        gs = ac.get("ground_speed")
        hdg = ac.get("track")
        lat = ac.get("latitude")
        lon = ac.get("longitude")

        track_rows += td("Altitude", f"{alt} ft" if alt is not None else None)
        if isinstance(gs, (int, float)):
            track_rows += td("Ground speed", f"{gs:.1f} kt")
        if isinstance(hdg, (int, float)):
            track_rows += td("Track", f"{hdg:.1f}°")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            track_rows += td("Position", f"{lat:.5f}, {lon:.5f}")
    else:
        track_rows = "<tr><td colspan='2'>No recent track for this ident.</td></tr>"

    # Metadata table (registration, type, etc.)
    if meta:
        reg = meta.get("registration")
        typecode = meta.get("typecode")
        model = meta.get("model")
        manufacturer = meta.get("manufacturerName")
        operator = meta.get("operator")
        country = meta.get("country")
        engines = meta.get("engines")

        type_line = " ".join(x for x in [typecode, model] if x)
        meta_rows = ""
        meta_rows += td("Registration", reg)
        meta_rows += td("Type / Model", type_line or None)
        meta_rows += td("Manufacturer", manufacturer)
        meta_rows += td("Operator", operator)
        meta_rows += td("Country", country)
        meta_rows += td("Engines", engines)
    else:
        msg = "No metadata available."
        if meta_error:
            msg += " (lookup error)"
        meta_rows = f"<tr><td colspan='2'>{msg}</td></tr>"

    # Data for the Leaflet map
    map_data = {
        "lat": ac.get("latitude") if ac else None,
        "lon": ac.get("longitude") if ac else None,
        "altitude": ac.get("altitude") if ac else None,
        "label": ac.get("callsign") or hex_code or ident_clean,
    }
    map_json = json.dumps(map_data)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8" />
      <title>Aircraft {ident_clean} – Sideband Watchtower</title>
      <link rel="stylesheet"
            href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
            integrity="sha256-p4NxAoJBhI0C2f2RTGPaMhF0zYK38nYuyj8vPqn+1po="
            crossorigin=""/>
      <style>
        body {{
          background: #050712;
          color: #e4e9ff;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0;
          padding: 20px;
        }}
        a.back-link {{
          color: #00d8ff;
          text-decoration: none;
        }}
        a.back-link:hover {{
          text-decoration: underline;
        }}
        h1 {{
          margin-top: 10px;
          margin-bottom: 10px;
        }}
        .grid {{
          display: grid;
          grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.4fr);
          gap: 18px;
          align-items: flex-start;
        }}
        .card {{
          background: #0b1020;
          border-radius: 10px;
          padding: 14px 18px;
          box-shadow: 0 0 10px rgba(0,0,0,0.5);
          border: 1px solid rgba(0,224,255,0.2);
        }}
        table.detail {{
          width: 100%;
          border-collapse: collapse;
          font-size: 14px;
        }}
        table.detail th {{
          text-align: left;
          font-weight: 500;
          padding: 4px 6px;
          width: 32%;
          color: #9fb3ff;
        }}
        table.detail td {{
          padding: 4px 6px;
        }}
        #map {{
          width: 100%;
          height: 320px;
          border-radius: 8px;
          border: 1px solid rgba(0,224,255,0.35);
          margin-top: 16px;
        }}
        .leaflet-container {{
          width: 100%;
          height: 100%;
          position: relative;
          overflow: hidden;
        }}
        .leaflet-tile {{
          position: absolute !important;
          width: 256px !important;
          height: 256px !important;
          max-width: none !important;
          box-sizing: content-box !important;
          border: none !important;
          padding: 0 !important;
          margin: 0 !important;
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



@app.get("/aircraft-reference", include_in_schema=False)
@app.get("/aircraft-reference/", include_in_schema=False)
def aircraft_reference(request: Request):
    # Works whether you access Watchtower via "osint:8000" or "192.168.x.x:8000"
    host = (request.headers.get("host") or "osint").split(":")[0]
    return RedirectResponse(url=f"http://{host}/ref/", status_code=302)














