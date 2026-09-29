"""
Seed the database with synthetic demonstration data and run detection.
Usage:
    cd sentinelai
    source venv/bin/activate
    python scripts/seed_demo_data.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import init_db, SessionLocal
from app.services.ingestion import ingest_events
from app.services.detection import run_detection
from app.services.alert_management import create_alerts_from_detections
from scripts.generate_sample_logs import generate_events


def main() -> None:
    print("=== SentinelAI — Demo Data Seeder ===\n")
    print("Step 1: Initializing database...")
    init_db()

    print("Step 2: Generating synthetic events...")
    events = generate_events()
    print(f"  Generated {len(events)} events")

    print("Step 3: Ingesting events into database...")
    db = SessionLocal()
    try:
        result = ingest_events(db, events, source_file="seed_demo_data.py")
        print(f"  {result.message}")
        if result.errors:
            print(f"  Errors: {result.errors[:5]}")

        print("Step 4: Running detection engine...")
        detections = run_detection(db)
        print(f"  Found {len(detections)} detections")

        print("Step 5: Creating alerts...")
        created = create_alerts_from_detections(db, detections)
        print(f"  Created {created} new alerts")

    finally:
        db.close()

    print("\n=== Demo data loaded successfully! ===")
    print("Start the backend: uvicorn app.main:app --reload")
    print("Start the dashboard: streamlit run dashboard/Home.py")


if __name__ == "__main__":
    main()
