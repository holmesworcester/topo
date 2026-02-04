# mTLS Pubkey Pinning (SQLite)

This document describes how to implement mutual TLS where acceptable peer identities are controlled by a SQLite database of pinned public keys.

**Goal**
- Encrypt all traffic with TLS (QUIC + rustls).
- Accept a connection only if the peer’s certificate public key is explicitly allowed.
- Scale to 100,000 peers without loading all keys into memory.

**Identity Source**
Use the certificate’s SubjectPublicKeyInfo (SPKI) as the peer identity. This is stable across certificate re-issuance and is small enough to hash and index.

**Storage**
Store only a hash of the SPKI in SQLite.

```sql
CREATE TABLE peer_keys (
  spki_hash BLOB PRIMARY KEY,  -- 32 bytes (blake2b)
  peer_id TEXT,
  created_at INTEGER
);

CREATE INDEX peer_keys_idx ON peer_keys (spki_hash);
```

**Verification Flow (incoming + outgoing)**
1. TLS verifier receives the peer certificate.
2. Extract the SPKI from the certificate.
3. Compute `hash = blake2b(spki)` (32 bytes).
4. Query SQLite:
   - `SELECT 1 FROM peer_keys WHERE spki_hash = ? LIMIT 1`
5. Accept only if a row exists.

**Bootstrap**
The invite link (out-of-band) must carry the peer’s public key (SPKI or raw public key).
On invite accept:
1. Decode the peer public key.
2. Convert to SPKI (if needed).
3. Compute `spki_hash`.
4. Insert into `peer_keys`.

**Observability**
On successful handshakes, log:
- `spki_hash` (hex or base64)
- optionally `peer_id` from the lookup row

This provides stable peer identification without trusting hostnames.

**Performance Notes**
- 100,000 peers with 32-byte hashes is small for SQLite.
- One indexed lookup per handshake is fast enough for typical connection rates.
- Optional: add a small LRU cache if handshake rate becomes a bottleneck.

