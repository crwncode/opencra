from datetime import datetime, timezone

from opencra_api.audit import compute_event_hash


def test_hash_chain_changes_with_payload() -> None:
    ts = datetime(2026, 9, 11, tzinfo=timezone.utc)
    a = compute_event_hash(
        prev_hash=None,
        payload={"x": 1},
        timestamp=ts,
        actor_id="u1",
        action="ingest",
    )
    b = compute_event_hash(
        prev_hash=a,
        payload={"x": 2},
        timestamp=ts,
        actor_id="u1",
        action="acknowledge",
    )
    assert a != b
    assert len(a) == 64
