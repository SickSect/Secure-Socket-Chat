# Security Design and Threat Model

This document describes how Secure Chat protects messages, which security
properties it actually provides, and which risks remain. It matches the code in
this repository (protocol v3, chat release v0.7).

> **Status:** educational / pre-production. The cryptographic constructions are
> implemented directly and covered by unit tests, but the project has not been
> independently audited. Do not use it for sensitive communications yet.

---

## 1. Scope and trust assumptions

The system has three parties:

| Party | Trust level | Sees |
|-------|-------------|------|
| Client A / Client B | trusted endpoints | plaintext, own private keys, locally pinned peer keys |
| Chat server | **honest-but-curious for message content**, trusted for routing; trusted for key lookup only until the client pins the key | metadata, ciphertext, public keys |
| Network / relay | untrusted | TLS ciphertext only |

TLS protects the client-server hop. End-to-end (E2E) encryption protects the
message body from the server and from anyone who can read server storage.

The server is **not** trusted to keep message contents secret. It is still
trusted to return the correct public key on **first contact**. The client pins
that key locally (trust on first use) and refuses any later key change until the
user explicitly accepts it. Users can detect a first-contact substitution by
comparing safety numbers over a separate channel. Key transparency, which would
remove the first-contact trust assumption, is not implemented
(see [§9](#9-known-limitations-and-residual-risks)).

---

## 2. Key hierarchy

| Key | Algorithm | Lifetime | Purpose |
|-----|-----------|----------|---------|
| Identity key | RSA ≥ 2048, SHA-256 signatures | Long-lived, per user | Authenticates the handshake; public half is stored on the server |
| Identity-key file | PBKDF2-HMAC-SHA256 (600k) + AES-256-GCM | Long-lived, per device | Protects the RSA private key at rest |
| Handshake ECDH keys | P-256 | One handshake, then reused as the initial ratchet pair | Produce the shared secret; become the first DH-ratchet keys |
| Ratchet root key | HKDF-SHA256 output | One session (idle 30 min / absolute 24 h) | Shared state of the DH ratchet; rekeyed on every rotation |
| Chain keys | HMAC-SHA256 output | Until the next DH rotation | One-way chain that mints a fresh key per message |
| Message keys | AES-256-GCM | Exactly one message | Encrypt a single payload, then are wiped |
| Confirmation tags | HKDF-SHA256 output | One handshake | Prove both sides derived the same transcript |
| Peer key pin | SHA-256 fingerprint | Until explicit re-trust | Detects a changed public key returned by the server |
| Safety number | SHA-256 over both identities and keys | Per peer pair | Out-of-band comparison of identity keys |
| JWT signing key | HMAC-SHA256, ≥ 32 bytes | Process lifetime or configured | Signs short-lived access tokens (10 min default) |
| Refresh tokens | 256-bit random, stored as HMAC-SHA256 hash | 30 days, single-use, rotated | Long-lived sessions; revocable per login family |

There is **no static pre-shared key** anymore. Earlier versions encrypted every
client-server frame with a PSK that was committed to the repository; that has
been removed. Transport confidentiality now comes exclusively from TLS 1.3.

---

## 3. End-to-end handshake (protocol v3)

`INIT_SESSION` (initiator → responder, via server):

1. Initiator fetches the responder's RSA identity key (`GET_KEY`).
2. Initiator generates an ephemeral P-256 key pair.
3. It signs
   `"secure-chat/v2/handshake" || role || initiator || responder || ephemeralPub`
   with its RSA identity key and sends the ephemeral public key + signature.

`SESSION_ACK` (responder → initiator):

1. Responder verifies the initiator's signature against the initiator's
   identity key.
2. Responder generates its own ephemeral P-256 key pair, computes the ECDH
   secret, and signs the same canonical payload with role `"ack"`.
3. Both sides compute a SHA-256 transcript hash over the canonical encoding of
   `(initiator, responder, initiatorEphemeralPub, responderEphemeralPub)`.
4. HKDF-SHA256 derives three values from the ECDH secret, using the
   transcript hash as salt and distinct `info` labels: the shared ratchet root
   key (`root`), `initiator-confirm` and `responder-confirm`.
5. The handshake ephemeral keys are kept as each side's initial ratchet key
   pair. The initiator's first message derives its sending chain from
   `KDF_RK(root, DH(initiatorEph, responderEph))`; the responder performs the
   identical step when that message arrives (creating its receiving chain) and
   immediately rotates — a fresh P-256 pair plus a sending chain for its reply.
6. Responder sends its ephemeral public key, signature, and confirmation tag in
   `SESSION_ACK`.

`SESSION_CONFIRM` (initiator → responder):

1. Initiator verifies the responder's signature, derives the same keys, and
   compares the responder's confirmation tag in constant time.
2. Initiator sends its own confirmation tag.
3. Only after receiving and verifying it does the responder mark the session
   `READY`.

Both sides require an explicit key confirmation before the session can carry
messages. This catches transcript mismatches and most handshake tampering.

### Why the handshake payload binds roles and both identities

The RSA signature covers a length-prefixed tuple of
`(label, role, signer, peer, ephemeralPublicKey)`. An `INIT_SESSION` captured
from Alice to Bob therefore cannot be replayed to Carol, or replayed in the
opposite direction: the signer/peer strings and the role label would no longer
match. It also prevents a responder's `SESSION_ACK` from being replayed as an
initiator message.

---

## 4. Message format, per-message keys and replay protection

Each E2E payload is Base64 of:

```
[version: 1 byte = 0x03][flags: 1][ratchetPub?: 65 bytes][sequence: 8][chainIndex: 8][IV: 12][AES-GCM ciphertext + 16-byte tag]
```

- `flags` bit 0 is set only on the first message after a rotation; the sender's
  fresh raw P-256 ratchet public key (65 bytes) then follows the flags byte.
- `sequence` is the global per-direction counter and must advance strictly by 1.
- `chainIndex` is the position inside the current HMAC chain and resets to `0`
  after every rotation.

The GCM additional authenticated data (AAD) authenticates the whole header:

```
version || flags || ratchetPub || lengthPrefixed(sender) || lengthPrefixed(recipient) || sequence || chainIndex
```

### Per-message keys (symmetric ratchet)

Every message advances a one-way HMAC-SHA256 chain:

```
messageKey_n = HMAC(chain_n, "…/msg-key")
chain_{n+1}  = HMAC(chain_n, "…/next-chain")
```

A leaked message key therefore opens exactly one message — neither the previous
nor the following ones, because HMAC cannot be inverted.

### DH ratchet (break-in recovery)

The shared root key only changes when a message arrives carrying the peer's
**fresh** ratchet public key:

```
step 1: (root, recvChain) = KDF_RK(root, DH(ownRatchetPriv, peerNewKey), peer→us)
step 2: ownRatchetPair = new P-256 pair
        (root, sendChain) = KDF_RK(root, DH(newOwnPriv, peerNewKey), us→peer)
```

Rotation is **receive-triggered only** — a side never rotates unilaterally —
so both peers apply the exact same sequence of root-key derivations and always
converge on identical chains. An attacker who steals a state snapshot still
cannot derive keys past the next rotation without the peer's fresh private key.

### Two-phase state updates

`beginSend()` / `planReceive()` compute everything into a ticket/plan first;
state is installed only by `commitSend()` / `commitReceive()` after the message
has been written to the wire or the GCM tag has been verified. A forged,
replayed or reordered message is therefore rejected **before** it can move the
ratchet, so an attacker cannot desynchronise a session.

Properties:

- **Per-message forward secrecy** — each message uses a fresh AES-256-GCM key
  derived one-way from its chain; a leaked key exposes only that message.
- **Break-in recovery** — the DH ratchet rekeys the root every round trip, so a
  stolen state snapshot stops being useful after the next rotation.
- **Strict sequence and chain index** — replay, reordering and gaps are rejected
  before any cryptographic work.
- **Directional chains** — `i2r` and `r2i` traffic never shares a chain key.
- **No key reuse across sessions** — the root is bound to the handshake
  transcript (both identities and both ephemeral keys), so a frame from one
  session cannot be decrypted in another.
- **Random 96-bit IV per message** — never reused under one message key.

The server also keeps a short-lived `(sender, nonce)` cache and rejects
timestamps older than 30 seconds. That check protects the routing layer from
naive replay/flood attempts; the E2E sequence counter is what actually protects
message integrity.

---

## 5. Transport security

- The REST API listens on HTTPS with TLS 1.3 only
  (`server.ssl.enabled-protocols: TLSv1.3`).
- The chat port uses an `SSLServerSocket` restricted to TLS 1.3.
- The client enables hostname verification
  (`endpointIdentificationAlgorithm=HTTPS`) and trusts a dedicated truststore
  (`TLS_TRUSTSTORE`), not the JVM default.
- Development certificates are generated locally by
  `certs/generate-dev-certs.ps1` and are gitignored.
- The server keystore and its password come from environment variables
  (`TLS_KEYSTORE`, `TLS_KEYSTORE_PASSWORD`, `TLS_KEY_PASSWORD`). Missing or
  empty values cause an explicit startup failure rather than an unencrypted
  fallback.

TLS protects metadata (who connects, when, message sizes) from the network.
It does **not** hide that metadata from the chat server itself.

---

## 6. Authentication and authorization

- Registration, login, refresh and logout are the only public REST endpoints.
  The security filter chain denies every other path by default.
- Passwords are hashed with BCrypt. Login performs a dummy BCrypt comparison
  for unknown usernames to reduce timing differences.
- Access JWTs are HMAC-SHA256, issued with a fixed issuer and validated for
  signature, issuer, expiry, subject, `jti` uniqueness and the `ver` claim
  (the user's `token_version`). Default lifetime is **10 minutes**
  (`JWT_EXPIRATION_MINUTES`); if `JWT_SECRET` is missing, too short, or one of
  the known public placeholders, the service generates a random per-process
  secret (fail-safe: tokens become invalid on restart).
- **Refresh tokens** (`POST /api/auth/refresh`) are 256-bit random values,
  **single-use**: every exchange rotates the token within the same login
  *family*. Only `HMAC-SHA256(JWT_SECRET, token)` is stored in the database.
  Replaying an already-rotated or revoked token is treated as theft and
  revokes the whole family (reuse detection).
- **Logout** (`POST /api/auth/logout`) revokes the token family and bumps
  `users.token_version`, which invalidates **every** outstanding access JWT
  immediately — including the one used for chat `JOIN`. Idempotent, and an
  unknown token reveals nothing.
- The chat server derives the username from the validated JWT, never from a
  client-supplied `JOIN` field. A client cannot claim another user's name.
- Registration rejects malformed or weak RSA keys (minimum 2048 bits, public
  exponent ≥ 65537).
- The public key registered for a username is the one the server returns to
  peers; a client cannot swap its key after registration.
- Auth endpoints are rate-limited per remote address (in-memory token buckets):
  register5/h, login10/h, refresh+logout30/h.
- Chat connections have a per-connection command budget (60 commands / 10 s)
  and bounded frame sizes (96 KiB).

### 6.1 Peer identity verification (TOFU + safety numbers)

The server is the key directory, so the client must not blindly trust a key it
receives. The client applies two independent checks:

1. **Trust on first use (TOFU).** The first public key seen for a username is
   pinned in `~/.secure-chat/known-peers.tsv` together with its SHA-256
   fingerprint. On every later `GET_KEY`, the client compares the returned key
   with the pin. A different key is rejected, kept only as an in-memory pending
   candidate, and the user sees a warning with both fingerprints.
2. **Safety number.** `/safety <user>` derives a deterministic 60-digit number
   from both usernames and both identity public keys. Both sides compute the
   same number. Users compare it over a channel the server does not control (in
   person, a phone call, a signed message). A mismatch means the server is
   showing different keys to the two sides.

Useful console commands:

| Command | Purpose |
|---------|---------|
| `/fingerprint` | Show this user's full identity-key fingerprint |
| `/safety <user>` | Show the safety number and the peer key fingerprint |
| `/trust <user> <prefix>` | Accept a changed key after out-of-band verification; at least 16 hex characters are required |
| `/rotate-key` | Replace this account's identity key (password re-auth); peers block until they re-verify |

The trust file is written atomically and restricted to owner read/write on
filesystems that support POSIX permissions. A sibling `known-peers.tsv.lock`
file serialises writers, and each save refreshes entries the process did not
change itself, so two chat windows opened from the same desktop account cannot
erase each other's pins. If the file is malformed, the client fails closed
instead of silently starting a new TOFU history.

**Key rotation.** `POST /api/auth/rotate-key` (chat command `/rotate-key`)
replaces the public identity key after step-up authentication: a live access
token **and** the account password are both required, so a stolen access token
alone cannot swap the key, and only the public half is uploaded — the private
half is generated on the client and stays in the local PBKDF2-encrypted file.
Peers pick the new key up on their next `GET_KEY`, which trips the TOFU check
above. A peer whose connection still caches the old key retries the signature
verification with a freshly fetched key (`ChatClientCore.verifyPeerSignature`),
so users see the explicit "key changed" flow instead of a bare
`BAD_SIGNATURE`. The client rolls its local key file back if the server
rejects the change, so the device and the key directory never disagree.

**Limitation:** first contact is still trust on first use. A malicious server
can substitute a key on the very first contact; only an out-of-band safety-number
comparison detects that. A future key-transparency log would let clients verify
that a key has been consistently published, without relying on a manual
comparison.

---

## 7. Secret storage and memory handling

- Identity private keys are encrypted at rest with PBKDF2-HMAC-SHA256
  (600,000 iterations) + AES-256-GCM. New files start with the `SCK1` magic and
  version marker; legacy files are still readable.
- Key files are written atomically (temp file + rename) and, on filesystems that
  support POSIX permissions, restricted to owner read/write (`0600`).
- Ratchet root keys, chain keys, per-message keys and confirmation tags are
  wrapped in `DestroyableSecretKey`; message keys are wiped immediately after
  each send/receive, the rest on expiry, failure or disconnect (best effort —
  the JVM may still copy arrays).
- Password character arrays are zeroed after use, and console input uses
  `System.console().readPassword()` when a terminal is available.
- JWTs and passwords are never logged.

---

## 8. Configuration hardening

Key defaults are fail-closed:

| Setting | Behaviour |
|---------|-----------|
| `JWT_SECRET` missing/weak | random per-process secret + warning |
| `TLS_KEYSTORE_PASSWORD` missing | startup error |
| `chat.tcp-port` / `SERVER_PORT` | explicit env configuration |
| JPA `ddl-auto` | `validate` (Flyway owns the schema) |
| SQL logging | disabled |
| Error responses | no stack traces, no exception class, no message |
| Unknown HTTP paths | denied by `SecurityConfig` |
| Frame size | capped on both client and server |
| Thread pools / maps | bounded with rejection or cleanup |

---

## 9. Known limitations and residual risks

These are real and should be addressed before any production use.

1. **First-contact key distribution still trusts the server.** The local TOFU
   pin blocks silent key changes after the first contact, and safety numbers let
   users detect a substitution. However, a malicious or compromised server can
   still return its own RSA key for Bob on the very first contact. Without an
   out-of-band safety-number comparison, that MITM is undetectable. Key
   transparency is not implemented.
2. **Strict in-order delivery; rotation only on receive.** The ratchet rekeys
   when a fresh peer key arrives (one round trip), so a stolen state snapshot
   still exposes the messages sent until that next rotation. There is no
   skipped-message key storage: a single dropped frame desynchronises the chain
   and the session must be re-established (rejected by design — the chat has no
   offline queue). Header encryption is not implemented either, so the server
   can observe sequence numbers and rotation cadence (it already sees message
   metadata).
3. **Safety-number verification is manual.** The client displays the number and
   explains how to compare it, but it cannot force users to do so. A user who
   skips verification gets TOFU protection against later key changes but not
   against a first-contact MITM.
4. **Coarse revocation granularity.** Access tokens are not individually
   revocable (by design — that is exactly why they live only 10 minutes).
   Logout bumps `users.token_version`, which logs the user out **on all
   devices at once** and revokes the refresh family: there is no per-device
   logout yet. There is also no password-change endpoint (the natural trigger
   for a version bump), expired `refresh_tokens` rows are not cleaned up
   automatically, and refresh tokens stay valid up to 30 days while idle
   (though they are single-use, stored hashed, and revocable).
5. **Metadata is visible to the server.** It sees usernames, who talks to whom,
   timestamps, and ciphertext lengths.
6. **In-memory rate limiting.** Limits are per process and keyed by
   `remoteAddr`; behind a reverse proxy every client may share one bucket, and
   multiple instances do not share state.
7. **Windows file ACLs.** POSIX `0600` is applied only where supported. On
   Windows the key file inherits the directory ACL; use BitLocker/EFS and a
   protected user profile.
8. **Best-effort memory wiping.** The JVM and GC may keep copies of key
   material. `DestroyableSecretKey` reduces but does not eliminate this.
9. **Legacy PBE v1 decryption remains** so old key files keep working. New
   files always use v2 parameters.
10. **Server-side nonce cache is bounded.** Under extreme load the cache is
    cleared to stay within its memory cap. E2E sequence numbers still prevent
    message replay; the server-side cache is only a coarse flood control.
11. **No message history or offline delivery.** The server forwards live
    traffic only; it does not store message bodies.
12. **Local development certificates are self-signed.** They are not suitable
    for production; use a real CA and protect the private key.

---

## 10. Verification

Build and run the non-Spring cryptographic tests:

```powershell
$env:JAVA_HOME="C:\path\to\jdk-23+"
.\gradlew.bat test --tests org.ugina.SessionCryptoTest `
  --tests org.ugina.SessionContextTest --tests org.ugina.CipherTest `
  --tests org.ugina.EcdhCryptoTest --tests org.ugina.HkdfCryptoTest `
  --tests org.ugina.RsaCryptoTest --tests org.ugina.RsaSignatureTest `
  --tests org.ugina.PbeUtilTest --tests org.ugina.FileBasedKeyStorageTest `
  --tests org.ugina.KeyFingerprintTest --tests org.ugina.SafetyNumberTest `
  --tests org.ugina.PeerTrustStoreTest --tests org.ugina.RatchetTest
```

Start the stack:

```powershell
Copy-Item .env.example .env   # then fill in DB and TLS values
powershell -ExecutionPolicy Bypass -File certs/generate-dev-certs.ps1
.\gradlew.bat bootRun
```

Check that TLS is actually used:

```powershell
openssl s_client -connect localhost:8443 -tls1_3
openssl s_client -connect localhost:5000 -tls1_3
```

---

## 11. Reporting

This is a learning project. If you find a flaw, open an issue with a minimal
reproduction and do not include real credentials or private keys.
