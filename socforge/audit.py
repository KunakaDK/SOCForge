from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .db import connect

GENESIS_HASH = "0" * 64


def append_audit(actor: str, action: str, object_type: str, object_id: str, details: dict[str, Any] | None = None, db_path: str | None = None) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    conn = connect(db_path)
    try:
        last = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = last["entry_hash"] if last else GENESIS_HASH
        canonical = "|".join([timestamp, actor, action, object_type, str(object_id), details_json, previous_hash])
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        cur = conn.execute(
            "INSERT INTO audit_log(timestamp,actor,action,object_type,object_id,details_json,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
            (timestamp, actor, action, object_type, str(object_id), details_json, previous_hash, entry_hash),
        )
        conn.commit()
        return {"id": cur.lastrowid, "timestamp": timestamp, "actor": actor, "action": action, "object_type": object_type, "object_id": str(object_id), "details": details or {}, "previous_hash": previous_hash, "entry_hash": entry_hash}
    finally:
        conn.close()


def verify_audit_chain(db_path: str | None = None) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    finally:
        conn.close()
    previous = GENESIS_HASH
    for row in rows:
        details_json = row["details_json"]
        canonical = "|".join([row["timestamp"], row["actor"], row["action"], row["object_type"], str(row["object_id"]), details_json, previous])
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if row["previous_hash"] != previous or row["entry_hash"] != expected:
            return {"valid": False, "checked_entries": row["id"], "failed_entry_id": row["id"], "reason": "Hash-chain verification failed."}
        previous = row["entry_hash"]
    return {"valid": True, "checked_entries": len(rows), "head_hash": previous}
