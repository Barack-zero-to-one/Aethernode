"""
AetherNode Rate Limiting — anti-abuse gate for /publish and /gossip/publish

_validate_publish_payload only proves SOME RSA keypair signed a payload —
anyone can generate one for free, so nothing bounds how much distinct,
validly-signed junk an attacker can get a relay to accept. Before gossip
existed, that only filled up the one relay it was sent to. With gossip,
insert_message_and_maybe_gossip faithfully forwards every accepted new
message to every trusted peer, who forward it further, so unbounded
ingestion on any single relay now floods the whole trust mesh, not just
itself.

A pure per-identity limit doesn't close this: an attacker can defeat it by
minting a fresh keypair per message (free, instant — a classic Sybil
bypass). This module layers two kinds of limit instead: a per-identity
token bucket (fairness — stops one identity from starving everyone else's
share) and a global token bucket (the actual backstop — bounds the absolute
worst case regardless of how many distinct identities an attacker uses,
since minting new identities doesn't grow the global budget).

Pure standard library, importable by both relay.py and gossip.py without
either importing the other.
"""

import time
import threading
from collections import OrderedDict


class _TokenBucket:
    """
    Not internally locked — callers serialize access via RateLimiter's own
    lock, since a single logical check often spans multiple buckets
    (global + per-identity) and must be atomic as a whole.
    """
    __slots__ = ("capacity", "refill_per_second", "tokens", "last_refill")

    def __init__(self, capacity: float, refill_per_second: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)

    def try_take(self) -> bool:
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def refund(self) -> None:
        self.tokens = min(self.capacity, self.tokens + 1.0)


class RateLimiter:
    """
    One global token bucket (the Sybil-resistant backstop) plus a bounded,
    LRU-evicted pool of per-identity buckets (fairness only — not a
    security boundary by itself: an attacker CAN defeat a per-identity
    limit by rotating identities, but then immediately runs into the global
    bucket instead, which they cannot defeat that way). The per-identity
    pool is capped at max_identities so an attacker minting unlimited
    identities can't turn the limiter's own bookkeeping into a memory-
    exhaustion vector — growing the pool past the cap evicts the least-
    recently-used entry instead of growing further.
    """

    def __init__(self, global_capacity: float, global_refill_per_second: float,
                 per_identity_capacity: float, per_identity_refill_per_second: float,
                 max_identities: int = 10_000):
        self._lock = threading.Lock()
        self._global = _TokenBucket(global_capacity, global_refill_per_second)
        self._per_identity_capacity = per_identity_capacity
        self._per_identity_refill = per_identity_refill_per_second
        self._max_identities = max_identities
        self._buckets: "OrderedDict[str, _TokenBucket]" = OrderedDict()

    def _get_or_create_bucket_locked(self, identity: str) -> _TokenBucket:
        bucket = self._buckets.get(identity)
        if bucket is None:
            bucket = _TokenBucket(self._per_identity_capacity, self._per_identity_refill)
            self._buckets[identity] = bucket
            if len(self._buckets) > self._max_identities:
                self._buckets.popitem(last=False)  # evict least-recently-used
        else:
            self._buckets.move_to_end(identity)
        return bucket

    def check_global(self) -> bool:
        """
        Global bucket only. Use alone, before expensive per-request work
        (e.g. signature verification) or before the caller-supplied
        identity is trustworthy — an unverified identity must never gate a
        per-identity check, or an attacker could grief a specific victim's
        fairness quota by spoofing their pubkey in unsigned garbage at zero
        cost.
        """
        with self._lock:
            return self._global.try_take()

    def check_identity(self, identity: str) -> bool:
        """Per-identity bucket only. Call only after check_global() already
        succeeded for this same request."""
        with self._lock:
            return self._get_or_create_bucket_locked(identity).try_take()

    def refund_global(self) -> None:
        """
        Call when check_global() succeeded but the request is being
        rejected anyway for another reason (e.g. a subsequent
        check_identity() failing). Without this, an identity that's over
        ITS OWN limit could still slowly drain the shared global budget
        through sheer repeated-attempt volume, even though every individual
        attempt is ultimately rejected.
        """
        with self._lock:
            self._global.refund()

    def allow(self, identity: str) -> bool:
        """
        Convenience for when the identity is ALREADY trustworthy at call
        time (e.g. an mTLS-verified peer fingerprint, unlike a client's
        self-declared, pre-signature-check sender_pubkey): both checks in
        one call, atomically, with the same refund-on-identity-failure
        behavior as the split check_global()/check_identity() path.
        """
        with self._lock:
            if not self._global.try_take():
                return False
            if self._get_or_create_bucket_locked(identity).try_take():
                return True
            self._global.refund()
            return False


def per_minute(capacity: float) -> float:
    """Converts a 'N per minute' config value into the refill_per_second
    a _TokenBucket needs, given capacity == N (a full minute's allowance
    available as an instant burst)."""
    return capacity / 60.0
