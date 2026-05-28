# Sideband Watchtower

Raspberry Pi ADS-B aircraft tracking and local OSINT dashboard.

## Current Status

Early prototype. Rebuild and cleanup are in progress to make this a reproducible, public portfolio repo.

## What It Does Today

- Ingests local ADS-B data from an SBS/BaseStation feed (typically `dump1090-fa` or `readsb` on port `30003`)
- Stores recent aircraft and events in SQLite
- Serves a local FastAPI dashboard with:
  - Leaflet map of currently tracked aircraft
  - aircraft/event views
  - basic detail pages for individual aircraft
- Optionally enriches aircraft metadata with OpenSky credentials

## Intended MVP (Rebuild Target)

- FastAPI backend with cleaner project structure
- Local web UI with Leaflet map
- First-run receiver configuration (latitude/longitude)
- Stable local ingestion from dump1090-fa/readsb
- SQLite persistence for sightings/config
- User-configurable scoring/ranking rules
- Raspberry Pi install and systemd deployment docs

## Hardware Requirements

- Raspberry Pi (model with reliable network and storage)
- RTL-SDR USB receiver
- 1090 MHz ADS-B antenna
- Local ADS-B decoder stack (`dump1090-fa` or `readsb`) providing SBS/BaseStation output

## Legal / Ethical Use

- Passive ADS-B reception only
- No transmitting
- No bypassing protected systems or paywalls
- User is responsible for compliance with local laws and regulations

## Privacy Note

- Do not commit your receiver location to source control
- Keep local coordinates and API credentials in `.env` (which is gitignored)
- Keep private/local operator notes out of public commits

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set your local values, especially:

- `RECEIVER_LAT`
- `RECEIVER_LON`
- (optional) `OPENSKY_CLIENT_ID` / `OPENSKY_CLIENT_SECRET`

Run the app:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open:

- `http://localhost:8000/`

Do not commit your `.env` file or private receiver coordinates.

## Configuration (Placeholder)

Configuration currently relies on environment variables (see `.env.example`), with receiver location and ADS-B feed endpoint planned for first-run setup.

## Roadmap (Placeholder)

- Phase 0: safety and public-repo scaffolding
- Phase 1: stable local run path
- Phase 2: first-run config page
- Phase 3: map/current aircraft MVP hardening
- Phase 4+: persistence, scoring, Pi deployment polish

## License

MIT (see `LICENSE`).
