from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from opencra_api.orm import AuditEvent


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(
    *,
    prev_hash: str | None,
    payload: dict,
    timestamp: datetime,
    actor_id: str,
    action: str,
) -> str:
    material = "|".join(
        [
            prev_hash or "",
            canonical_json(payload),
            timestamp.isoformat(),
            actor_id,
            action,
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()


def append_event(
    db: Session,
    *,
    org_id: str,
    actor_id: str,
    action: str,
    payload: dict,
    case_id: str | None = None,
) -> AuditEvent:
    last = (
        db.query(AuditEvent)
        .filter(AuditEvent.org_id == org_id)
        .order_by(AuditEvent.created_at.desc())
        .first()
    )
    now = datetime.now(timezone.utc)
    prev = last.event_hash if last else None
    event = AuditEvent(
        org_id=org_id,
        case_id=case_id,
        actor_id=actor_id,
        action=action,
        payload=payload,
        prev_hash=prev,
        event_hash=compute_event_hash(
            prev_hash=prev,
            payload=payload,
            timestamp=now,
            actor_id=actor_id,
            action=action,
        ),
        created_at=now,
    )
    db.add(event)
    db.flush()
    return event
