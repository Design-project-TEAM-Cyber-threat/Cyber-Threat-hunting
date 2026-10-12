r"""
Real-data API demo.

The Django server must be running:
    python manage.py runserver

Usage:
    python backend\demo_api.py
        -> sends synthetic demo flows

    python backend\demo_api.py "data\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv" 10
        -> sends 10 real CICIDS2017 flows

    python backend\demo_api.py "data\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv" 500
        -> sends 500 real CICIDS2017 flows

Uses standard library plus pandas/numpy.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd


# Make the project root importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml.features import REQUIRED_COLUMNS


BASE = "http://127.0.0.1:8000/api"


def call(method, path, body=None):
    """
    Send an HTTP request to the Django API.
    """
    data = (
        json.dumps(body, allow_nan=False).encode("utf-8")
        if body is not None
        else None
    )

    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response_data = response.read()
            return response.status, json.loads(response_data)

    except urllib.error.HTTPError as error:
        try:
            error_data = json.loads(error.read() or b"{}")
        except Exception:
            error_data = {}

        return error.code, error_data

    except Exception as error:
        print(f"\nAPI request failed: {error}")
        raise


def load_flows(csv_path, n):
    """
    Load real CICIDS2017 flows from a CSV file.
    """
    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(
            f"CSV file not found: {csv_path}"
        )

    print(f"Reading CSV: {csv_path}")
    print("This may take some time for a large CICIDS2017 file...")

    df = pd.read_csv(
        csv_path,
        low_memory=False,
    )

    print(f"CSV loaded: {len(df):,} rows")

    # Clean column names.
    df.columns = df.columns.str.strip()

    # Keep only the columns required by the ML pipeline.
    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            "Required columns are missing from the CSV:\n"
            + "\n".join(missing)
        )

    df = df[REQUIRED_COLUMNS]

    # Remove invalid numerical values.
    df = (
        df
        .replace([np.inf, -np.inf], np.nan)
        .dropna()
    )

    if len(df) == 0:
        raise ValueError(
            "No valid rows remain after preprocessing."
        )

    # Select a reproducible sample.
    number_of_flows = min(n, len(df))

    df = df.sample(
        number_of_flows,
        random_state=1,
    )

    # Convert every field to a normal Python float.
    flows = [
        {
            key: float(value)
            for key, value in row.items()
        }
        for row in df.to_dict("records")
    ]

    return flows


def synthetic_flows(n=300):
    """
    Generate synthetic demo flows when no CSV is supplied.
    """
    from ml.synthetic_world import typical_flow

    rng = np.random.default_rng(1)

    flows = [
        typical_flow(
            rng,
            port=int(
                rng.choice(
                    [443, 80, 22]
                )
            ),
        )
        for _ in range(n)
    ]

    # Add a few intentionally unusual flows.
    flows += [
        typical_flow(
            rng,
            port=22,
            rate_factor=500.0,
        )
        for _ in range(10)
    ]

    return flows


def main():
    """
    Main demo execution.
    """

    # ---------------------------------------------------------
    # 1. Load data
    # ---------------------------------------------------------

    if len(sys.argv) > 1:
        csv_path = sys.argv[1]

        number_of_flows = (
            int(sys.argv[2])
            if len(sys.argv) > 2
            else 500
        )

        flows = load_flows(
            csv_path,
            number_of_flows,
        )

        print(
            f"\nSending {len(flows)} real CICIDS2017 flows..."
        )

    else:
        flows = synthetic_flows()

        print(
            f"\nNo CSV given: sending "
            f"{len(flows)} SYNTHETIC demo flows "
            f"(not real traffic)..."
        )

    # ---------------------------------------------------------
    # 2. Send flows to API
    # ---------------------------------------------------------

    batch_size = 500

    for start in range(
        0,
        len(flows),
        batch_size,
    ):
        batch = flows[
            start:start + batch_size
        ]

        batch_number = (
            start // batch_size
        ) + 1

        print(
            f"\nSending batch {batch_number} "
            f"({len(batch)} flows)..."
        )

        status, output = call(
            "POST",
            "/score/",
            {
                "flows": batch
            },
        )

        print(
            "Batch result:",
            status,
            output.get(
                "counts",
                output,
            ),
        )

    # ---------------------------------------------------------
    # 3. Bad-request validation
    # ---------------------------------------------------------

    bad_status, bad_output = call(
        "POST",
        "/score/",
        {
            "flows": [
                {
                    "Destination Port": 80
                }
            ]
        },
    )

    print(
        "\nBad request check:",
        bad_status,
        "(expected 400)",
    )

    # ---------------------------------------------------------
    # 4. Summary
    # ---------------------------------------------------------

    summary_status, summary = call(
        "GET",
        "/summary/",
    )

    print(
        "\nSummary HTTP status:",
        summary_status,
    )

    print(
        "Summary:",
        json.dumps(
            summary,
            indent=2,
        ),
    )

    # ---------------------------------------------------------
    # 5. Get highest-risk alert
    # ---------------------------------------------------------

    listing_status, listing = call(
        "GET",
        "/alerts/?ordering=risk&page_size=1",
    )

    if listing.get("results"):
        alert_id = listing["results"][0]["id"]

        detail_status, detail = call(
            "GET",
            f"/alerts/{alert_id}/",
        )

        print(
            "\nHighest-risk alert:"
        )

        print(
            "Risk level:",
            detail["risk_level"],
        )

        print(
            "Risk score:",
            detail["risk_score"],
        )

        print(
            "Service:",
            detail["context"]["service"],
        )

        print(
            "\nExplanation:"
        )

        print(
            detail["explanation"]
        )

        print(
            "\nRecommended response:",
            detail["recommended_response"],
        )

        print(
            "Automated action:",
            detail["automated_action"],
        )

    else:
        print(
            "\nNo Medium/High alerts were returned."
        )


if __name__ == "__main__":
    main()