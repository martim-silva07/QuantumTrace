from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from dotenv import load_dotenv
from pymongo import ASCENDING, MongoClient, UpdateOne
from pymongo.collection import Collection
from pymongo.database import Database

load_dotenv(Path(__file__).resolve().parent / ".env")

DB_NAME = "Junctionx"
SCANS_COLLECTION = "Scans"
ASSETS_COLLECTION = "Assets"

DEFAULT_URI = (
    os.environ.get("MONGODB_URI")
    or os.environ.get("MONGO_URI")
    or "mongodb+srv://Martim:1234567890@junctionx.0yole3c.mongodb.net/"
)


def get_client(uri: str | None = None) -> MongoClient:
    """Create the MongoDB client. Uses the env var if present."""
    return MongoClient(uri or os.environ.get("MONGODB_URI") or os.environ.get("MONGO_URI") or DEFAULT_URI)


def get_db(client: MongoClient | None = None) -> Database:
    mongo_client = client or get_client()
    return mongo_client[DB_NAME]


def ensure_indexes(db: Database) -> None:
    scans = db[SCANS_COLLECTION]
    scans.create_index([("started_at", ASCENDING)])
    scans.create_index([("status", ASCENDING)])

    assets = db[ASSETS_COLLECTION]
    assets.create_index([("fingerprint", ASCENDING)], unique=True)
    assets.create_index([("algorithm", ASCENDING)])
    assets.create_index([("risk_tier", ASCENDING)])
    assets.create_index([("source", ASCENDING)])


def start_scan(db: Database, sources: list[str], target: str) -> str:
    doc = {
        "started_at": datetime.now(timezone.utc),
        "finished_at": None,
        "status": "running",
        "sources": sources,
        "target": target,
        "findings": [],
        "summary": {},
    }
    result = db[SCANS_COLLECTION].insert_one(doc)
    return str(result.inserted_id)


def finish_scan(
    db: Database,
    scan_id: str,
    findings: Iterable[Any],
    summary: dict[str, Any] | None = None,
    status: str = "completed",
) -> None:
    from bson import ObjectId

    docs = [getattr(f, "to_dict", lambda: f)() for f in findings]
    db[SCANS_COLLECTION].update_one(
        {"_id": ObjectId(scan_id)},
        {
            "$set": {
                "finished_at": datetime.now(timezone.utc),
                "status": status,
                "findings": docs,
                "summary": summary or {},
            }
        },
    )


def upsert_assets(db: Database, findings: Iterable[Any]) -> int:
    now = datetime.now(timezone.utc)
    ops: list[UpdateOne] = []
    for f in findings:
        d = getattr(f, "to_dict", lambda: f)()
        fp = d.pop("fingerprint")
        ops.append(
            UpdateOne(
                {"fingerprint": fp},
                {
                    "$setOnInsert": {**d, "fingerprint": fp, "first_seen": now},
                    "$set": {
                        "last_seen": now,
                        "risk_tier": d.get("risk_tier"),
                        "nist_migration": d.get("nist_migration"),
                    },
                    "$inc": {"times_seen": 1},
                },
                upsert=True,
            )
        )
    if not ops:
        return 0
    result = db[ASSETS_COLLECTION].bulk_write(ops, ordered=False)
    return result.upserted_count + result.modified_count


def get_assets(
    db: Database,
    risk_tier: str | None = None,
    source: str | None = None,
    algorithm: str | None = None,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {}
    if risk_tier:
        query["risk_tier"] = risk_tier
    if source:
        query["source"] = source
    if algorithm:
        query["algorithm"] = algorithm
    return list(db[ASSETS_COLLECTION].find(query))


def count_by_risk_tier(db: Database) -> dict[str, int]:
    pipeline = [{"$group": {"_id": "$risk_tier", "count": {"$sum": 1}}}]
    return {r["_id"] or "unknown": r["count"] for r in db[ASSETS_COLLECTION].aggregate(pipeline)}


def count_by_algorithm(db: Database) -> list[dict[str, Any]]:
    pipeline = [
        {"$group": {"_id": "$algorithm", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return [{"algorithm": r["_id"], "count": r["count"]} for r in db[ASSETS_COLLECTION].aggregate(pipeline)]


def get_scans(db: Database, limit: int = 20) -> list[dict[str, Any]]:
    return list(db[SCANS_COLLECTION].find({}, {"findings": 0}).sort("started_at", -1).limit(limit))


def get_scan(db: Database, scan_id: str) -> dict[str, Any] | None:
    from bson import ObjectId
    return db[SCANS_COLLECTION].find_one({"_id": ObjectId(scan_id)})
