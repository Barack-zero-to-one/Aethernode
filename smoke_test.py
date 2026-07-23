"""
AetherNode Smoke Tests

Fast, pure-logic validation of the crypto/protocol/relay-storage layer:
real RSA-2048 signing and verification, real AES-256-GCM encryption, real
on-disk SQLite (for the parts that need to observe actual file bytes), but
no sockets, no subprocesses, no Tor. This is what CI runs on every push,
on every supported OS, because it finishes in seconds rather than minutes.

The heavier, real-socket integration tests (simulate_partition.py,
stress_test_quota.py, stress_test_quota_multiday.py) require a POSIX host
for AF_UNIX and are run separately — see .github/workflows/ci.yml.

Run directly with:
    python smoke_test.py
"""
import base64
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

import relay
import gossip
import client
import protocol
from cryptography.hazmat.primitives.asymmetric import rsa

FAILURES = []


def check(name, cond):
    if cond:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}")
        FAILURES.append(name)


def build_signed_payload(sender_priv, recipient_pub_b64, message, ttl_seconds=3600, day_offset=0):
    """day_offset=0 means addressed with TODAY's blind id (the normal case);
    a nonzero offset simulates a message that was actually addressed on a
    past day, for testing the multi-day fetch/delete logic."""
    recipient_pub = client.b64_to_pubkey(recipient_pub_b64)
    enc = client.encrypt_message(message, recipient_pub)
    day = protocol.day_bucket(datetime.now(timezone.utc) - timedelta(days=day_offset))
    payload = {
        "version": "1",
        "sender_pubkey": client.pubkey_to_b64(sender_priv.public_key()),
        "recipient_id": protocol.blind_recipient_id(base64.b64decode(recipient_pub_b64), day),
        "encrypted_key": enc["encrypted_key"],
        "nonce": enc["nonce"],
        "ciphertext": enc["ciphertext"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(),
    }
    payload["signature"] = client.sign_payload(payload, sender_priv)
    return payload


def build_delete_payload(priv, target_signature):
    payload = {
        "version": "1",
        "action": "delete",
        "target_signature": target_signature,
        "recipient_pubkey": client.pubkey_to_b64(priv.public_key()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload["signature"] = client.sign_payload(payload, priv)
    return payload


def main() -> int:
    print("Generating test keypairs...")
    sender_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_pub_b64 = client.pubkey_to_b64(recipient_priv.public_key())
    recipient_pub_der = base64.b64decode(recipient_pub_b64)
    recipient_id = protocol.blind_recipient_id(recipient_pub_der, protocol.day_bucket(datetime.now(timezone.utc)))

    default_max_ttl = relay.DEFAULT_MAX_TTL_SECONDS

    # ─── 0. Rotating blind identifiers ──────────────────────────────────────
    print("\n[0] blind_recipient_id / day_bucket")

    today = protocol.day_bucket(datetime.now(timezone.utc))
    yesterday = protocol.day_bucket(datetime.now(timezone.utc) - timedelta(days=1))
    id_today = protocol.blind_recipient_id(recipient_pub_der, today)
    id_yesterday = protocol.blind_recipient_id(recipient_pub_der, yesterday)
    id_today_again = protocol.blind_recipient_id(recipient_pub_der, today)

    check("blind id is deterministic for the same (pubkey, day)", id_today == id_today_again)
    check("blind id differs across different days for the same recipient", id_today != id_yesterday)
    check("blind id output is 64 hex chars (same shape as the static address it replaces)",
          len(id_today) == 64 and all(c in "0123456789abcdef" for c in id_today))

    other_pub_der = base64.b64decode(client.pubkey_to_b64(sender_priv.public_key()))
    check("blind id differs across different pubkeys for the same day",
          protocol.blind_recipient_id(other_pub_der, today) != id_today)

    # ─── 1. TTL validation (_validate_publish_payload) ──────────────────────
    print("\n[1] TTL validation (_validate_publish_payload)")
    relay._MIN_TTL_SECONDS = 60
    relay._MAX_TTL_SECONDS = default_max_ttl

    good = build_signed_payload(sender_priv, recipient_pub_b64, "hello", ttl_seconds=3600)
    check("valid TTL (1h) accepted", relay._validate_publish_payload(good) is None)

    too_short = build_signed_payload(sender_priv, recipient_pub_b64, "hello", ttl_seconds=5)
    err = relay._validate_publish_payload(too_short)
    check("TTL below MIN_TTL rejected", err is not None and "expires_at" in err)

    too_long = build_signed_payload(sender_priv, recipient_pub_b64, "hello", ttl_seconds=99 * 24 * 3600)
    err = relay._validate_publish_payload(too_long)
    check("TTL above MAX_TTL rejected", err is not None and "expires_at" in err)

    missing_field = dict(good)
    del missing_field["expires_at"]
    err = relay._validate_publish_payload(missing_field)
    check("missing expires_at rejected", err is not None and "Missing fields" in err)

    tampered = dict(good)
    tampered["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    err = relay._validate_publish_payload(tampered)
    check("tampered expires_at (breaks signature) rejected", err is not None)

    plus5 = timezone(timedelta(hours=5))
    non_utc = dict(good)
    non_utc["expires_at"] = (datetime.now(plus5) + timedelta(hours=1)).isoformat()
    non_utc["signature"] = client.sign_payload({k: v for k, v in non_utc.items() if k != "signature"}, sender_priv)
    err = relay._validate_publish_payload(non_utc)
    check("non-UTC offset expires_at (+05:00) rejected", err is not None and "UTC offset" in err)

    addressed_yesterday = build_signed_payload(sender_priv, recipient_pub_b64, "still valid",
                                                ttl_seconds=3600, day_offset=1)
    check("message addressed with yesterday's blind id still validates",
          relay._validate_publish_payload(addressed_yesterday) is None)
    check("...and its recipient_id is indeed yesterday's, not today's",
          addressed_yesterday["recipient_id"] == id_yesterday)

    # ─── 2. Delete-request validation (_validate_delete_payload) ───────────
    print("\n[2] Delete-request validation (_validate_delete_payload)")

    del_payload = build_delete_payload(recipient_priv, good["signature"])
    check("valid delete payload accepted", relay._validate_delete_payload(del_payload) is None)

    del_bad_sig = dict(del_payload)
    del_bad_sig["target_signature"] = "tampered"
    err = relay._validate_delete_payload(del_bad_sig)
    check("tampered delete payload rejected", err is not None)

    del_wrong_action = dict(del_payload)
    del_wrong_action["action"] = "publish"
    del_wrong_action["signature"] = client.sign_payload(
        {k: v for k, v in del_wrong_action.items() if k != "signature"}, recipient_priv
    )
    err = relay._validate_delete_payload(del_wrong_action)
    check("wrong action rejected", err is not None and "action" in err)

    # ─── 3. Quota logic (real file-backed DB) ───────────────────────────────
    print("\n[3] check_recipient_quota (real on-disk SQLite)")
    quota_db_path = REPO_ROOT / "_smoke_quota_test.db"
    if quota_db_path.exists():
        quota_db_path.unlink()
    db = relay.init_db(str(quota_db_path))
    lock = threading.Lock()

    ok = gossip.check_recipient_quota(db, lock, recipient_id, max_messages=3, max_bytes=10_000_000)
    check("empty recipient passes quota", ok is True)

    now = datetime.now(timezone.utc).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    for i in range(3):
        db.execute(
            "INSERT INTO messages (recipient_id, sender_pubkey, signature, payload, expires_at, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (recipient_id, "x", f"sig-{i}", "x" * 100, future, now),
        )
    db.commit()

    ok = gossip.check_recipient_quota(db, lock, recipient_id, max_messages=3, max_bytes=10_000_000)
    check("recipient at max_messages cap rejected", ok is False)

    ok = gossip.check_recipient_quota(db, lock, recipient_id, max_messages=10, max_bytes=250)
    check("recipient at max_bytes cap rejected", ok is False)

    db.execute("DELETE FROM messages")
    db.commit()
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    for i in range(5):
        db.execute(
            "INSERT INTO messages (recipient_id, sender_pubkey, signature, payload, expires_at, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (recipient_id, "x", f"expired-sig-{i}", "x" * 100, expired, now),
        )
    db.commit()
    ok = gossip.check_recipient_quota(db, lock, recipient_id, max_messages=3, max_bytes=10_000_000)
    check("EXPIRED-but-unswept rows still count against quota (bypass closed)", ok is False)

    db.execute("DELETE FROM messages")
    db.commit()

    # ─── 3b. Atomic quota re-check inside insert_message_and_maybe_gossip ──
    print("\n[3b] insert_message_and_maybe_gossip atomic quota re-check")
    for i in range(2):
        m = build_signed_payload(sender_priv, recipient_pub_b64, f"fill-{i}", ttl_seconds=3600)
        is_new, row_id, quota_exceeded = gossip.insert_message_and_maybe_gossip(
            db, lock, m, recipient_id, now, None, quota_max_messages=2, quota_max_bytes=10_000_000,
        )
        check(f"insert #{i} within cap succeeds", is_new is True and quota_exceeded is False)

    m3 = build_signed_payload(sender_priv, recipient_pub_b64, "overflow", ttl_seconds=3600)
    is_new, row_id, quota_exceeded = gossip.insert_message_and_maybe_gossip(
        db, lock, m3, recipient_id, now, None, quota_max_messages=2, quota_max_bytes=10_000_000,
    )
    check("insert past cap is rejected atomically (quota_exceeded=True)", is_new is False and quota_exceeded is True)
    row = db.execute("SELECT 1 FROM messages WHERE signature=?", (m3["signature"],)).fetchone()
    check("...and the rejected message was NOT actually inserted", row is None)

    m4 = build_signed_payload(sender_priv, recipient_pub_b64, "unlimited", ttl_seconds=3600)
    is_new, row_id, quota_exceeded = gossip.insert_message_and_maybe_gossip(
        db, lock, m4, recipient_id, now, None,
    )
    check("insert with no quota params bypasses quota entirely", is_new is True and quota_exceeded is False)

    db.execute("DELETE FROM messages")
    db.commit()

    # ─── 4. resolve_deletion_request two-phase resolution ───────────────────
    print("\n[4] resolve_deletion_request (two-phase pending/confirmed, day-search)")

    sig_a = "sig-pending-match"
    db.execute(
        "INSERT INTO deletion_requests (target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (sig_a, recipient_pub_b64, "", now),
    )
    db.commit()
    discard = gossip.resolve_deletion_request(db, lock, sig_a, recipient_id, default_max_ttl)
    check("pending request matching TODAY's recipient_id -> discard (True)", discard is True)
    row = db.execute("SELECT confirmed FROM deletion_requests WHERE target_signature=?", (sig_a,)).fetchone()
    check("...and promoted to confirmed=1", row is not None and row[0] == 1)

    sig_a2 = "sig-pending-match-yesterday"
    db.execute(
        "INSERT INTO deletion_requests (target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (sig_a2, recipient_pub_b64, "", now),
    )
    db.commit()
    discard = gossip.resolve_deletion_request(db, lock, sig_a2, id_yesterday, default_max_ttl)
    check("pending request matching a NON-today day-bucket -> discard (True), day-search works", discard is True)

    sig_b = "sig-pending-mismatch"
    db.execute(
        "INSERT INTO deletion_requests (target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (sig_b, client.pubkey_to_b64(attacker_priv.public_key()), "", now),
    )
    db.commit()
    discard = gossip.resolve_deletion_request(db, lock, sig_b, recipient_id, default_max_ttl)
    check("pending request from a DIFFERENT pubkey (no day matches) -> proceed (False)", discard is False)
    row = db.execute("SELECT 1 FROM deletion_requests WHERE target_signature=?", (sig_b,)).fetchone()
    check("...and the bogus pending row is cleaned up", row is None)

    sig_c = "sig-already-confirmed"
    db.execute(
        "INSERT INTO deletion_requests (target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
        "VALUES (?, ?, ?, 1, ?)",
        (sig_c, recipient_pub_b64, recipient_id, now),
    )
    db.commit()
    discard = gossip.resolve_deletion_request(db, lock, sig_c, recipient_id, default_max_ttl)
    check("already-confirmed tombstone -> discard (True)", discard is True)

    discard = gossip.resolve_deletion_request(db, lock, "sig-no-request-at-all", recipient_id, default_max_ttl)
    check("no deletion_requests row -> proceed (False)", discard is False)

    db.execute("DELETE FROM deletion_requests")
    db.commit()

    # ─── 5. handle_delete_request authorization (day-search) ───────────────
    print("\n[5] handle_delete_request (authorization + oracle-resistance, day-search)")

    msg = build_signed_payload(sender_priv, recipient_pub_b64, "secret content", ttl_seconds=3600)
    gossip.insert_message_and_maybe_gossip(db, lock, msg, recipient_id, now, None)

    wrong_delete = build_delete_payload(attacker_priv, msg["signature"])
    resp, did_confirm = gossip.handle_delete_request(db, lock, wrong_delete, default_max_ttl)
    check("attacker delete on someone else's message -> not confirmed", did_confirm is False)
    check("...response indistinguishable from not-found", resp == {"status": "delete_requested"})
    row = db.execute("SELECT 1 FROM messages WHERE signature=?", (msg["signature"],)).fetchone()
    check("...and the message is NOT deleted", row is not None)
    pending_row = db.execute(
        "SELECT 1 FROM deletion_requests WHERE target_signature=?", (msg["signature"],)
    ).fetchone()
    check("...and NO deletion_requests row was written for the wrong owner", pending_row is None)

    unknown_delete = build_delete_payload(recipient_priv, "signature-that-does-not-exist-yet")
    resp, did_confirm = gossip.handle_delete_request(db, lock, unknown_delete, default_max_ttl)
    check("delete for not-yet-arrived signature -> pending, not confirmed", did_confirm is False)
    check("...response is delete_requested", resp == {"status": "delete_requested"})
    row = db.execute(
        "SELECT confirmed FROM deletion_requests WHERE target_signature=?",
        ("signature-that-does-not-exist-yet",)
    ).fetchone()
    check("...and a PENDING (confirmed=0) row was recorded", row is not None and row[0] == 0)

    right_delete = build_delete_payload(recipient_priv, msg["signature"])
    resp, did_confirm = gossip.handle_delete_request(db, lock, right_delete, default_max_ttl)
    check("owner delete -> confirmed", did_confirm is True)
    check("...response is deleted/async", resp == {"status": "deleted", "propagation": "async"})
    row = db.execute("SELECT 1 FROM messages WHERE signature=?", (msg["signature"],)).fetchone()
    check("...and the message row is actually gone", row is None)
    row = db.execute(
        "SELECT confirmed FROM deletion_requests WHERE target_signature=?", (msg["signature"],)
    ).fetchone()
    check("...and a CONFIRMED tombstone exists", row is not None and row[0] == 1)

    resp2, did_confirm2 = gossip.handle_delete_request(db, lock, right_delete, default_max_ttl)
    check("repeat delete on already-deleted message -> idempotent, not confirmed again", did_confirm2 is False)
    row = db.execute(
        "SELECT confirmed FROM deletion_requests WHERE target_signature=?", (msg["signature"],)
    ).fetchone()
    check("...confirmed tombstone still intact (not downgraded)", row is not None and row[0] == 1)

    msg_past = build_signed_payload(sender_priv, recipient_pub_b64, "old message", ttl_seconds=3600, day_offset=2)
    gossip.insert_message_and_maybe_gossip(db, lock, msg_past, msg_past["recipient_id"], now, None)
    past_delete = build_delete_payload(recipient_priv, msg_past["signature"])
    resp, did_confirm = gossip.handle_delete_request(db, lock, past_delete, default_max_ttl)
    check("owner delete on a message addressed 2 days ago -> confirmed via day-search", did_confirm is True)
    row = db.execute("SELECT 1 FROM messages WHERE signature=?", (msg_past["signature"],)).fetchone()
    check("...and that message row is actually gone", row is None)

    db.close()
    quota_db_path.unlink()

    # ─── 6. Multi-day fetch (IN clause) ─────────────────────────────────────
    print("\n[6] Multi-day fetch-equivalent query")
    fetch_db_path = REPO_ROOT / "_smoke_fetch_test.db"
    if fetch_db_path.exists():
        fetch_db_path.unlink()
    db = relay.init_db(str(fetch_db_path))
    lock = threading.Lock()

    for offset in (0, 1, 3):
        m = build_signed_payload(sender_priv, recipient_pub_b64, f"day-{offset}-message",
                                  ttl_seconds=3600, day_offset=offset)
        gossip.insert_message_and_maybe_gossip(db, lock, m, m["recipient_id"], now, None)

    candidate_ids = [
        protocol.blind_recipient_id(recipient_pub_der,
                                     protocol.day_bucket(datetime.now(timezone.utc) - timedelta(days=d)))
        for d in range(5)  # today through 4 days back -- covers offsets 0, 1, 3 above
    ]
    placeholders = ",".join("?" * len(candidate_ids))
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = db.execute(
        f"SELECT payload FROM messages WHERE recipient_id IN ({placeholders}) AND expires_at > ? ORDER BY id ASC",
        (*candidate_ids, now_iso)
    ).fetchall()
    recovered_texts = set()
    for row in rows:
        payload = json.loads(row[0])
        recovered_texts.add(client.decrypt_message(payload, recipient_priv))
    check("multi-day IN-clause query recovers messages from all 3 different day-buckets",
          recovered_texts == {"day-0-message", "day-1-message", "day-3-message"})

    db.close()
    fetch_db_path.unlink()

    # ─── 7. Database audit: raw-byte forensic check ─────────────────────────
    print("\n[7] Database audit — raw file bytes after secure delete")
    audit_db_path = REPO_ROOT / "_smoke_audit_test.db"
    if audit_db_path.exists():
        audit_db_path.unlink()

    marker = "UNMISTAKABLE_MARKER_STRING_8f3a91"
    db = relay.init_db(str(audit_db_path))

    marker_msg = build_signed_payload(sender_priv, recipient_pub_b64, marker, ttl_seconds=3600)
    db.execute(
        "INSERT INTO messages (recipient_id, sender_pubkey, signature, payload, expires_at, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (recipient_id, "sender-x", "audit-sig-1",
         json.dumps({**marker_msg, "_raw_marker": marker}),
         (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), now),
    )
    db.commit()

    raw_bytes_before = audit_db_path.read_bytes()
    check("marker IS present in file before delete (sanity check)", marker.encode() in raw_bytes_before)

    db.execute("DELETE FROM messages WHERE signature = ?", ("audit-sig-1",))
    db.commit()
    db.close()

    raw_bytes_after = audit_db_path.read_bytes()
    check("marker is ABSENT from raw file bytes after secure delete", marker.encode() not in raw_bytes_after)

    audit_db_path.unlink()

    # ─── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
