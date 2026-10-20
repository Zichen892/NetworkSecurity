"""Opt-in MongoDB connectivity check. No connection is made on import."""

from __future__ import annotations

import os
import sys


def main() -> int:
    uri = os.environ.get("MONGO_DB_URL")
    if not uri:
        print("Set MONGO_DB_URL before running this check.", file=sys.stderr)
        return 2
    try:
        from pymongo import MongoClient
    except ImportError:
        print("Install the optional dependency with pip install '.[mongo]'", file=sys.stderr)
        return 2
    try:
        with MongoClient(uri, serverSelectionTimeoutMS=5000) as client:
            client.admin.command("ping")
        print("MongoDB ping succeeded.")
        return 0
    except Exception:
        # Driver exceptions can include server details. Keep public logs minimal.
        print("MongoDB ping failed. Check the connection and credentials privately.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
