#!/usr/bin/env python3
import os
import sys
import requests

CLIENT_ID_ENV = "OPENSKY_CLIENT_ID"
CLIENT_SECRET_ENV = "OPENSKY_CLIENT_SECRET"
_missing_creds_warned = False

TOKEN_URL = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"
META_URL  = "https://opensky-network.org/api/metadata/aircraft/icao/{}"
ROUTE_URL = "https://opensky-network.org/api/routes"

def _get_opensky_creds():
    client_id = os.getenv(CLIENT_ID_ENV, "").strip()
    client_secret = os.getenv(CLIENT_SECRET_ENV, "").strip()
    return client_id, client_secret

def opensky_enrichment_enabled():
    client_id, client_secret = _get_opensky_creds()
    return bool(client_id and client_secret)

def _warn_missing_creds_once():
    global _missing_creds_warned
    if _missing_creds_warned:
        return
    print(
        "[OpenSky] enrichment disabled: set OPENSKY_CLIENT_ID and "
        "OPENSKY_CLIENT_SECRET to enable metadata lookups.",
        flush=True,
    )
    _missing_creds_warned = True

def get_token():
    client_id, client_secret = _get_opensky_creds()
    if not client_id or not client_secret:
        _warn_missing_creds_once()
        return None

    r = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]

def get_aircraft_meta(token, icao):
    r = requests.get(
        META_URL.format(icao.lower()),
        headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()

def get_route(token, callsign):
    # Optional: if you also know the callsign (e.g. UAL123)
    r = requests.get(
        ROUTE_URL,
        params={"callsign": callsign},
        headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()

def main():
    if len(sys.argv) < 2:
        print("Usage: icao_lookup.py A30C46 [CALLSIGN]")
        sys.exit(1)

    icao = sys.argv[1]
    callsign = sys.argv[2] if len(sys.argv) > 2 else None

    token = get_token()
    if not token:
        print("OpenSky credentials are not configured.")
        sys.exit(1)

    meta = get_aircraft_meta(token, icao)
    print("=== AIRCRAFT META ===")
    print(meta or "No metadata found")

    if callsign:
        route = get_route(token, callsign)
        print("\n=== ROUTE INFO ===")
        print(route or "No route info found")

if __name__ == "__main__":
    main()
