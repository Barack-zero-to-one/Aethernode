"""
AetherNode Protocol Constants

Shared between client.py and relay.py so the two can never silently drift
out of sync. Deliberately pure standard library — relay.py must not gain a
dependency on client-only libraries (PySocks) by importing this module.
"""

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
