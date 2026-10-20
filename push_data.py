"""Optional, explicitly authorized upload of the local feature dataset to MongoDB."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from networksecurity.phishing import FEATURES, _read_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or upload the local phishing feature CSV")
    parser.add_argument("--data", type=Path, default=Path("Network_Data/phisingData.csv"))
    parser.add_argument("--database", default="network_security")
    parser.add_argument("--collection", default="phishing_features")
    parser.add_argument("--write", action="store_true", help="Explicitly insert rows into MongoDB")
    args = parser.parse_args(argv)
    try:
        labeled_rows = _read_rows(args.data, labeled=True)
        if not args.write:
            print(f"Dry run: {len(labeled_rows)} rows available. Add --write to insert into MongoDB.")
            return 0
        uri = os.environ.get("MONGO_DB_URL")
        if not uri:
            raise ValueError("Set MONGO_DB_URL in the environment before using --write")
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise ValueError("Install the optional dependency with pip install '.[mongo]'") from exc
        try:
            with MongoClient(uri, serverSelectionTimeoutMS=5000) as client:
                client.admin.command("ping")
                collection = client[args.database][args.collection]
                for start in range(0, len(labeled_rows), 500):
                    batch = [dict(zip(FEATURES, features), Result=label)
                             for features, label in labeled_rows[start:start + 500]]
                    collection.insert_many(batch)
        except Exception:
            # Driver errors may include server details. Keep public logs minimal.
            print("MongoDB import failed. Check connection and data privately.", file=sys.stderr)
            return 1
        print(f"Inserted {len(labeled_rows)} rows into {args.database}.{args.collection}.")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"push_data: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
