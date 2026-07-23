"""
AetherNode Protocol Constants

Shared between client.py and relay.py so the two can never silently drift
out of sync. Deliberately pure standard library — relay.py must not gain a
dependency on client-only libraries (PySocks) by importing this module.
"""

import hashlib
import hmac
from datetime import datetime, timezone

# Every plaintext is padded to one of these sizes before AES-256-GCM
# encryption, so ciphertext length alone can't be used to infer message
# content or type. See client.py's pad_plaintext/unpad_plaintext.
PAD_BUCKETS = (4 * 1024, 16 * 1024, 64 * 1024)  # 4 KB / 16 KB / 64 KB

# Worst-case size of a published JSON payload, derived from the largest
# padding bucket: padded plaintext -> AES-GCM ciphertext+tag (+16 bytes) ->
# base64 (4 chars per 3 bytes) plus the other signed fields (sender_pubkey,
# encrypted_key, signature, recipient_id, timestamp, JSON punctuation),
# measured at roughly 1.3 KB. relay.py derives its POST body-size cap from
# this value directly, instead of a hand-copied constant, so the two files
# can never fall out of sync with each other.
_LARGEST_CIPHERTEXT_BYTES = PAD_BUCKETS[-1] + 16  # + AES-GCM authentication tag
_LARGEST_CIPHERTEXT_B64_BYTES = 4 * ((_LARGEST_CIPHERTEXT_BYTES + 2) // 3)
_JSON_FIELD_OVERHEAD_BYTES = 1_320
MAX_PUBLISH_BODY_BYTES = _LARGEST_CIPHERTEXT_B64_BYTES + _JSON_FIELD_OVERHEAD_BYTES


# ─── Rotating Blind Recipient Identifiers (metadata-hiding) ──────────────────
# The relay indexes and serves messages by recipient_id, but must never be
# able to derive a permanent, unkeyed mapping from a recipient's identity to
# every message ever addressed to them just by grouping repeated identifier
# values in its own database. blind_recipient_id() replaces the earlier
# static SHA-256(pubkey) address with a value that also depends on the UTC
# calendar day, so an observer with database/log access but no specific
# user's public key can only ever cluster "same day" traffic, not a user's
# entire retention-window history. Shared here (not duplicated separately in
# client.py and gossip.py, which must never import each other) so both sides
# of the protocol can never silently compute this differently.
#
# This does NOT hide anything from an adversary who already has (or later
# obtains) the target's public key: a pubkey is not a secret — it must be
# shared for anyone to message that person at all — so such an adversary can
# always recompute every candidate day within a relay's retention window
# (at most a few dozen HMAC calls) and fully reconstruct history regardless
# of rotation. Rotation only raises the bar for an observer who never had
# the key in the first place. See README § Data Retention for the complete,
# precisely-stated threat model, including what this deliberately does not
# protect (sender_pubkey is unrotated; deleting a message reveals your real
# key to the relay and its peers).

def blind_recipient_id(pubkey_der: bytes, day: str) -> str:
    """
    HMAC-SHA256(key=pubkey_der, msg=day), hex-encoded — same 64-hex-char
    shape as the static address it replaces, so no downstream length bound
    changes. HMAC, not a bare hash of the concatenation: HMAC is the
    standard, side-channel-considered construction for a keyed hash and
    avoids ever having to reason about concatenation-ambiguity edge cases.
    Note (not a weakness, just worth knowing before "optimizing" this):
    RSA-2048 SubjectPublicKeyInfo DER exceeds SHA-256's 64-byte HMAC block
    size, so per RFC 2104 the key is pre-hashed internally by hmac itself to
    SHA-256(pubkey_der) before use — numerically identical to the address
    this function replaces. That's exactly HMAC's defined behavior for long
    keys and doesn't weaken it as a PRF.
    """
    return hmac.new(pubkey_der, day.encode(), hashlib.sha256).hexdigest()


def day_bucket(dt: datetime) -> str:
    """UTC calendar day, e.g. '2026-07-22' — the rotation unit blind_recipient_id
    is keyed on. Synchronized across all users (everyone's addresses change at
    the same UTC boundary) rather than staggered per-user, which avoids
    leaking an individual's own rotation-timing pattern as a side channel."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
