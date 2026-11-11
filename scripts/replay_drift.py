#!/usr/bin/env python3
"""Local CLI utility to replay synthetic Cloud Asset Inventory drift events or Nightly Sweeps
against a locally running WAF Auditor FastAPI server (or directly in-process via ASGITransport).

Usage examples:
  # 1. List available synthetic CAI drift fixtures:
  uv run python scripts/replay_drift.py --list

  # 2. Dry-run envelope generation (prints the Pub/Sub push JSON payload without sending):
  uv run python scripts/replay_drift.py --fixture open_ssh_firewall --dry-run

  # 3. Send a real-time drift event to a locally running uvicorn server:
  uv run python scripts/replay_drift.py --fixture open_ssh_firewall --url http://127.0.0.1:8080/pubsub/push

  # 4. Trigger a nightly baseline sweep against a specific org/project:
  uv run python scripts/replay_drift.py --mode NIGHTLY_SWEEP --org-id organizations/123456789
"""

import argparse
import base64
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_FILE = ROOT_DIR / "tests" / "fixtures" / "cai_drift_samples.json"


def load_fixtures() -> dict:
    if not FIXTURES_FILE.exists():
        raise FileNotFoundError(f"Fixtures file not found: {FIXTURES_FILE}")
    return json.loads(FIXTURES_FILE.read_text(encoding="utf-8"))


def build_pubsub_envelope(payload: dict) -> dict:
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return {
        "message": {
            "data": encoded,
            "messageId": f"local-replay-{uuid.uuid4().hex[:8]}",
            "publishTime": datetime.now(timezone.utc).isoformat(),
        },
        "subscription": f"projects/{os.getenv('GOOGLE_CLOUD_PROJECT', 'waf-compliance-hub')}/subscriptions/waf-auditor-push-sub",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay synthetic CAI drift events or Nightly Sweeps against the WAF Auditor."
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available synthetic CAI drift fixtures in tests/fixtures/cai_drift_samples.json.",
    )
    parser.add_argument(
        "--fixture",
        type=str,
        default="open_ssh_firewall",
        help="Fixture name from cai_drift_samples.json (e.g., 'open_ssh_firewall', 'zonal_unbacked_cloudsql').",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["REALTIME_DRIFT", "NIGHTLY_SWEEP"],
        default="REALTIME_DRIFT",
        help="Trigger mode: REALTIME_DRIFT (uses --fixture) or NIGHTLY_SWEEP.",
    )
    parser.add_argument(
        "--org-id",
        type=str,
        default=os.getenv("WAF_TARGET_SCOPE") or os.getenv("WAF_ORG_ID", "organizations/123456789"),
        help="Organization ID for NIGHTLY_SWEEP mode.",
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://127.0.0.1:8080/pubsub/push",
        help="Target FastAPI /pubsub/push endpoint URL.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="HTTP request timeout in seconds (default: 300s).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the decoded payload and base64 Pub/Sub push envelope without sending an HTTP request.",
    )

    args = parser.parse_args()
    fixtures = load_fixtures()

    if args.list:
        print("Available synthetic CAI drift fixtures:")
        for name, data in fixtures.items():
            asset = data.get("asset", {})
            print(f"  - {name:26s} | {asset.get('assetType')} | {asset.get('name')}")
        return 0

    if args.mode == "REALTIME_DRIFT":
        if args.fixture not in fixtures:
            print(
                f"Error: Fixture '{args.fixture}' not found. Choose from: {', '.join(fixtures.keys())}",
                file=sys.stderr,
            )
            return 1
        payload = fixtures[args.fixture]
    else:
        payload = {
            "scan_mode": "NIGHTLY_SWEEP",
            "org_id": args.org_id,
        }

    envelope = build_pubsub_envelope(payload)

    if args.dry_run:
        print("=== Decoded Event Payload ===")
        print(json.dumps(payload, indent=2))
        print("\n=== Pub/Sub Push Envelope ===")
        print(json.dumps(envelope, indent=2))
        return 0

    print(f"Sending {args.mode} event to {args.url} ...")
    try:
        with httpx.Client(timeout=args.timeout) as client:
            response = client.post(args.url, json=envelope)
        print(f"HTTP {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        return 0 if response.is_success else 1
    except httpx.ConnectError:
        print(
            f"\nConnection failed: No server listening at {args.url}.\n"
            "Start the server first in another terminal:\n"
            "  uv run uvicorn app.main:app --reload --port 8080",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
