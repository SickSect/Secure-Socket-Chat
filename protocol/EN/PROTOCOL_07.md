# Secure Chat — Protocol Specification v3 (v0.7)

Status: current for release **v0.7**.
Previous versions: [`PROTOCOL_06.md`](PROTOCOL_06.md) (v2), [`PROTOCOL_05.md`](PROTOCOL_05.md).

> **Compatibility:** E2E protocol v3 is **incompatible** with v0.6 clients: a
> old client rejects a frame with `ver = 3`, a new one rejects `ver = 2`
> (`Unsupported E2E payload version`). Both sides must be upgraded together.

---

## 1. Overview

Secure Chat consists of two independent channels:

1. **REST API over HTTPS** — registration and login, JWT issuance.
2. **TCP chat over TLS 1.3** — JOIN, handshake, message exchange.

Message content is additionally end-to-end encrypted (E2E) on the clients. The
server sees only metadata and the opaque `e2ePayload`.

What changed in v3 compared to v2:

| v2 | v3 |
|----|----|
| Two directional AES keys for the whole session | **A key per message** from a one-way HMAC chain |
| No key rotation inside a session | **DH ratchet** every turn: new root + new chains |
| Frame `[ver][seq][IV][CT]` | `[ver][flags][ratchetPub?][seq][chainIdx][IV][CT]` |
| AAD: names + sequence | AAD: flag + ratchet key + names + sequence + chainIndex |
| Forward secrecy at session level only | Per-message FS + break-in recovery |
| Handshake ephemerals destroyed after handshake | Handshake ephemerals become the **initial ratchet pair** |

Unchanged: transport, framing, REST authentication, the command set, the
handshake messages (`INIT_SESSION`/`SESSION_ACK`/`SESSION_CONFIRM`), RSA
signatures, timeouts, error codes.

---

## 2. Transport and framing

- REST: HTTPS, TLS 1.3 only, default port `8443`.
- Chat: TLS 1.3, default port `5000`.
- A frame is one UTF-8 line terminated by `\n`. `\r` is ignored.
- Maximum frame length — **96 KiB** (96 × 1024 characters) on both client and
  server. Exceeding it closes the connection.
- JSON is encoded by Jackson. Unknown fields are ignored.
- The client verifies the TLS hostname
  (`endpointIdentificationAlgorithm=HTTPS`) and uses a dedicated truststore
  (`TLS_TRUSTSTORE`).

---

## 3. Authentication (REST)

Changes in v0.7: the password now yields a **token pair** — a short-lived
access JWT plus a single-use refresh token; `/refresh` and `/logout` were
added.

### POST /api/auth/register

Unchanged from v2 — see
[`PROTOCOL_06.md`, section 3](PROTOCOL_06.md#3-authentication-rest)
(request `username/password/publicKey`, `201` response, `400/409/429` errors).

### POST /api/auth/login

Request — unchanged. `200 OK` response:

```json
{
  "token": "<access JWT>",
  "expiresAt": 1760000000000,
  "refreshToken": "<43 base64url characters>",
  "refreshExpiresAt": 1762592000000
}
```

Errors: `401` (`AUTHENTICATION_FAILED`), `429` (`RATE_LIMIT_EXCEEDED`).

### POST /api/auth/refresh

Exchanges a single-use refresh token for a new pair (rotation):

```json
{ "refreshToken": "vnk1Jm4ZpOBK4xy6..." }
```

`200 OK` — the same shape as login (a fresh pair). Errors:

- `401 INVALID_TOKEN` — the token is unknown, expired **or already used**;
  presenting a spent/revoked token is treated as theft and revokes the whole
  login *family* (reuse detection);
- `400 VALIDATION_FAILED` — blank field;
- `429 RATE_LIMIT_EXCEEDED` —30/hour per IP (shared with `/logout`).

### POST /api/auth/logout

```json
{ "refreshToken": "vnk1Jm4ZpOBK4xy6..." }
```

`200 OK`:

```json
{ "status": "logged_out" }
```

Effect: revokes the whole token **family** and bumps `users.token_version`,
which immediately kills **every** outstanding access JWT (chat `JOIN`
included). Idempotent: an unknown token also returns `200` (no validity
oracle). `429` shares the `/refresh` bucket.

### POST /api/auth/rotate-key

Identity-key rotation (step-up: **live session + password**):

```json
{ "password": "...", "publicKey": "<Base64 RSA ≥ 2048>" }
```

Header: `Authorization: Bearer <access JWT>` — required: the caller is taken
from the token, which is checked for signature, expiry and `ver`.

`200 OK` response:

```json
{ "status": "key_rotated", "username": "alice" }
```

Errors:

- `401 INVALID_TOKEN` — bearer token missing, garbage or revoked;
- `401 AUTHENTICATION_FAILED` — wrong password (shares the rate-limit bucket
  with `/login`: 10/hour per IP — one password-guessing budget);
- `409 REGISTRATION_FAILED` — invalid key (below 2048 bits, bad exponent,
  malformed encoding);
- `400 VALIDATION_FAILED` — blank fields.

The private half is generated **on the client** and never sent to the server
(otherwise E2E would be pointless). After rotation the next `GET_KEY` returns
the new key: every peer trips its TOFU check ("key changed" → blocked until
`/trust`), and a client still holding the old key in its cache retries the
signature verification with a freshly fetched key
(`ChatClientCore.verifyPeerSignature`), so users see the explicit key-change
flow instead of a bare `BAD_SIGNATURE`.

### Access JWT

- algorithm HS256, issuer `secure-chat`, `sub` = username;
- claims: `jti` (UUID — every token is unique even within the same second),
  `iat`, `exp` (`JWT_EXPIRATION_MINUTES`, default **10 minutes**),
  `ver` = `users.token_version`;
- validation: signature + issuer + expiry + `sub`; additionally `ver` is
  compared against the database on **every** use (chat `JOIN` included) — a
  mismatch yields `INVALID_TOKEN`. Bumping `token_version` is an instant
  revocation of all outstanding tokens.

### Refresh token

-32 random bytes → base64url (43 characters), lifetime `REFRESH_TOKEN_DAYS`
  (default30 days);
- the database stores **only** `token_hash = HMAC-SHA256(JWT_SECRET, token)`
  (a database leak yields no live tokens, and without `JWT_SECRET` an attacker
  cannot even verify a guess);
- all tokens from one login share a `family_id`;
- single use: every `/refresh` marks the row `rotated_at` and creates a new
  row in the same family;
- revocation: on `/logout` (whole family) or on reuse detection (whole family).

Schema — migration `V3__token_revocation.sql`:
`refresh_tokens(id, token_hash UNIQUE, family_id, user_id FK, expires_at,
created_at, rotated_at, revoked_at)` plus `users.token_version`.

---

## 4. Client → server messages (`ClientMessage`)

Unchanged from v2 — see
[`PROTOCOL_06.md`, section 4](PROTOCOL_06.md#4-client--server-messages-clientmessage):
`JOIN`, `GET_KEY`, `INIT_SESSION`, `SESSION_ACK`, `SESSION_CONFIRM`,
`SEND_MESSAGE`, `QUIT` with the same field limits.

---

## 5. Server → client messages (`ServerMessage`)

Unchanged from v2 — see
[`PROTOCOL_06.md`, section 5](PROTOCOL_06.md#5-server--client-messages-servermessage):
`SYSTEM`, `DM`, `DELIVERED`, `ERROR`, `PUBLIC_KEY`, `INIT_SESSION`,
`SESSION_ACK`, `SESSION_CONFIRM`.

The server treats `e2ePayload` as an opaque string (only non-emptiness and
length are checked) — only the client knows the frame version and layout.

---

## 6. Handshake v3

Notation:

- `A` — initiator, `B` — responder.
- `ID_A`, `ID_B` — usernames.
- `(E_A, e_A)`, `(E_B, e_B)` — ephemeral P-256 pairs of the handshake; they
  also become each side's **initial ratchet pair**.
- `K` — the ECDH shared secret.
- `H` — SHA-256 of the transcript.
- `root` — the shared ratchet root key.

### 6.1. Canonical signing payload

Before signing, a length-prefixed string is built:

```
LABEL = "secure-chat/v3/handshake"
payload = len(LABEL)||LABEL || len(role)||role || len(signer)||signer ||
          len(peer)||peer || len(ephemeralPub)||ephemeralPub
```

`len(x)` is 4 bytes big-endian. All strings are UTF-8.

- The initiator signs `role = "init"`, `signer = ID_A`, `peer = ID_B`,
  `ephemeralPub = E_A`.
- The responder signs `role = "ack"`, `signer = ID_B`, `peer = ID_A`,
  `ephemeralPub = E_B`.

The signature is `SHA256withRSA` with the identity key. Binding the role and
both identities prevents replaying a captured INIT to another peer or in the
opposite direction.

### 6.2. Transcript and root derivation

```
transcript = len("secure-chat/v3/transcript") ||
             len(ID_A) || len(ID_B) || len(E_A) || len(E_B)

H = SHA-256(transcript)
```

HKDF-SHA256 (`HkdfCrypto.derive`):

```
root              = HKDF(K, salt = H, info = "secure-chat/v3/root",              32)
initiator-confirm = HKDF(K, salt = H, info = "secure-chat/v3/initiator-confirm", 32)
responder-confirm = HKDF(K, salt = H, info = "secure-chat/v3/responder-confirm", 32)
```

The confirmation tags (`conf_A`, `conf_B`) are compared in constant time
(`MessageDigest.isEqual`), as in v2.

### 6.3. Initial ratchet chains

Directions: `i2r` — initiator → responder, `r2i` — responder → initiator.

DHKDF step (`SessionCrypto.kdfRk`):

```
prk     = HMAC-SHA256(key = root, message = dhSecret)
newRoot = HMAC-SHA256(key = prk, message = "secure-chat/v3/ratchet/<dir>/root")
chain   = HMAC-SHA256(key = prk, message = "secure-chat/v3/ratchet/<dir>/chain")
```

The initiator, **lazily on its first send** (`SessionContext.beginSend`):

```
(root, CK_i2r) = kdfRk(root, DH(e_A, E_B), dir = "i2r")
```

The responder, **when the first message arrives** (`SessionContext.planReceive`):

```
step 1: (root, CK_i2r) = kdfRk(root, DH(e_B, E_A), dir = "i2r")  ← identical to A's step
step 2: (E_B2, e_B2)   = fresh P-256 pair
        (root, CK_r2i) = kdfRk(root, DH(e_B2, E_A), dir = "r2i")
```

Since `DH(e_A, E_B) == DH(e_B, E_A)` and the `dir` label matches the chain
direction, both sides obtain the **same** `root` and `CK_i2r`. From there the
rotation proceeds in strict alternation (see 7.3).

### 6.4. Sequence

```
A                                   server                                   B
|-- JOIN(jwt) ------------------------>|                                      |
|<-- SYSTEM(Welcome) ------------------|                                      |
|-- GET_KEY(bob) --------------------->|                                      |
|<-- PUBLIC_KEY(bob, rsaB) ------------|                                      |
|-- INIT_SESSION(bob, E_A, sig_A) ---->|-- INIT_SESSION(alice, E_A, sig_A) -->|
|                                      |<-- SESSION_ACK(alice, E_B, sig_B, conf_B)
|<-- SESSION_ACK(bob, E_B, sig_B, conf_B)                                      |
|-- SESSION_CONFIRM(bob, conf_A) ----->|-- SESSION_CONFIRM(alice, conf_A) --->|
|-- SEND_MESSAGE(bob, ver=3, flag, E_A, seq=0, idx=0, ...) -->|
|                                      |              |-- DM(alice, ver=3, flag, E_A, seq=0, idx=0, ...) -->|
```

Steps:

1. `A` fetches `rsaB`, generates `(E_A, e_A)`, signs the payload and sends
   `INIT_SESSION`.
2. `B` verifies `A`'s signature against `rsaA` (fetched via `GET_KEY`).
3. `B` generates `(E_B, e_B)`, computes `K`, `H` and `root`, signs
   `role="ack"`, computes `conf_B` and sends `SESSION_ACK`.
4. `A` verifies `B`'s signature, computes `K`, `H` and `root`, compares
   `conf_B` in constant time. On success it sends `SESSION_CONFIRM` with
   `conf_A` and then marks the session `READY`.
5. `B` compares `conf_A` in constant time and only then marks the session
   `READY`.

The session is not used for messages until confirmation completes. The
handshake ephemeral pairs are **not destroyed** — they become the initial
ratchet pair (see 6.3 and 7.3).

### 6.5. Simultaneous handshake

Unchanged: the lexicographically smaller username keeps the initiator role;
the other side discards its pending context and answers as responder
(`ChatClientCore.shouldAcceptIncomingHandshake`).

---

## 7. E2E message format (v3)

### 7.1. Frame

`e2ePayload` is Base64 of:

```
+--------+-------+--------------------+-----------+-------------+-------+-----------------------------+
| ver(1) | flags | ratchetPub(65)?    | seq(8,BE) | chainIndex(8) | IV(12)| AES-256-GCM ciphertext+tag |
+--------+-------+--------------------+-----------+-------------+-------+-----------------------------+
```

- `ver = 3`.
- `flags` — bit 0 (`0x01`) means "this frame carries a fresh ratchet key";
  all other bits are reserved and **must be zero** (otherwise the frame is
  rejected).
- `ratchetPub` — raw uncompressed P-256 point `0x04 || X(32) || Y(32)`,
  present only when `flags & 0x01`.
- `seq` — the global per-direction counter, strictly `+1`.
- `chainIndex` — position inside the current HMAC chain; resets to `0` after
  each rotation.

Minimum frame length: `1+1+8+8+12+16 = 46` bytes; with a ratchet key —
`46 + 65 = 111` bytes.

### 7.2. AAD

```
AAD = ver(1) || flags(1) || len(ratchetPub)(4) || ratchetPub ||
      len(sender)(4) || sender || len(recipient)(4) || recipient ||
      seq(8, BE) || chainIndex(8, BE)
```

The entire header is authenticated: the rotation flag, the ratchet key, the
sender identity, `sequence` and `chainIndex` cannot be silently modified.

### 7.3. Message keys and rotation

The symmetric ratchet (`SessionCrypto.kdfCk`) runs on **every** message:

```
messageKey_n = HMAC-SHA256(key = chain_n, message = "secure-chat/v3/msg-key")
chain_{n+1}  = HMAC-SHA256(key = chain_n, message = "secure-chat/v3/next-chain")
```

HMAC is one-way: knowing `messageKey_n` or `chain_{n+1}` does not reveal the
previous values — past messages stay closed forever.

The DH ratchet (`SessionCrypto.kdfRk`, steps from 6.3) runs **only when a
message arrives with a fresh peer ratchet key** (`flags & 0x01`):

```
step 1: (root, recvChain) = kdfRk(root, DH(own current pair, peerNewKey), dir = incoming)
step 2: own pair = fresh P-256 pair
        (root, sendChain) = kdfRk(root, DH(own new pair, peerNewKey), dir = outgoing)
```

Convergence rules (mandatory for implementations):

1. **Receive-triggered rotation only.** A side never rotates on its own — only
   in response to the peer's fresh key. Both sides therefore apply the same
   sequence of KDF steps and their roots/chains cannot diverge. (Simultaneous
   unilateral rotation by both peers would break convergence — verified during
   design.)
2. `dir` is the chain direction (`i2r`/`r2i`) and is the same on both sides
   for the same step.
3. The first message of each direction carries `flags = 0x01`: the initiator's
   initial `E_A` (lazy chain), the responder's `E_B2` (step 2 of 6.3).
   Subsequent messages until the next rotation carry `flags = 0`.

### 7.4. Two-phase state updates

Sending (`beginSend` → `commitSend`):

1. `beginSend`: if `sendChain` is empty — a lazy `kdfRk`; then `kdfCk`; a
   **ticket** is produced (sequence, chainIndex, messageKey, ratchetPub?,
   nextSendChain). No state changes yet.
2. Encryption and writing to the socket.
3. `commitSend`: counters and chain advance; the message key is wiped.

Receiving (`planReceive` → `commitReceive`):

1. `planReceive`: `seq == lastReceived + 1` check; on `flags & 0x01` — the
   point is validated on the curve and the ratchet steps are **computed**;
   `chainIndex` check; `messageKey` derivation. Everything goes into a
   **plan**.
2. The GCM tag is verified separately.
3. `commitReceive`: state changes only after successful verification.

Consequence: a forged/replayed frame is rejected **before** any state change —
an attacker cannot desynchronise the ratchet.

### 7.5. Receive rules

1. Length ≥ 46 bytes (≥ 111 with the flag) after Base64 decoding.
2. `ver == 3`; unknown `flags` bits → reject.
3. `seq == lastReceived + 1` (strictly, no gaps or reordering).
4. `chainIndex == (flag ? 0 : current recvChainIndex)`.
5. On flag: the point is valid and lies on `secp256r1`.
6. The GCM tag matches.
7. Only after items 3–6 is the state (counters, chains, root, pair) updated
   and `lastReceived` incremented.

Failing any item → the frame is dropped and state is unchanged
(`DECRYPTION_FAILED` on the receiving side).

The nonce and timestamp in `SEND_MESSAGE` are an additional coarse server-side
defence (60-second `(sender, nonce)` cache, ±30 s clock tolerance).

### 7.6. Delivery order

The protocol **requires strict ordering** per direction: a dropped frame
rejects the following ones (the chain desynchronises by construction). There
is no offline queue; on desynchronisation the session is re-established with a
new handshake. This is a deliberate limitation (see `SECURITY.md`, §9).

---

## 8. Session lifecycle

- `WAITING_FOR_ACK` — initiator sent INIT.
- `WAITING_FOR_CONFIRM` — responder sent ACK and waits for CONFIRM.
- `READY` — keys confirmed, messages may be sent.
- `FAILED` — handshake rejected or destroyed.

Timeouts:

- idle — 30 minutes without activity;
- absolute — 24 hours from creation.

On expiry the session is destroyed together with all ratchet material (root,
chains, pair), and the next message starts a new handshake. On client
disconnect all sessions are destroyed.

Rotation cadence: the root is rekeyed on every ratchet-key change, i.e. once
per turn (a burst of messages in one direction). Message keys change on
**every** message.

Server (unchanged):

- connection idle timeout — 30 minutes;
- command budget — 60 per 10 seconds per connection;
- thread pool — 8–64 threads, queue 256; connections are rejected on
  overflow;
- one concurrent connection per username.

---

## 9. Error codes

Unchanged from v2 — see
[`PROTOCOL_06.md`, section 9](PROTOCOL_06.md#9-error-codes):
`INVALID_NAME`, `NAME_TAKEN`, `INVALID_PUBLIC_KEY`, `RECIPIENT_OFFLINE`,
`EXPIRED`, `REPLAY`, `DECRYPTION_FAILED`, `INVALID_FORMAT`, `RATE_LIMITED`,
`INTERNAL_ERROR`, `INVALID_TOKEN`.

---

## 10. Security properties

Provided:

- content confidentiality from the server and the network (E2E + TLS);
- message integrity and authenticity (GCM + AAD over the whole header);
- **per-message forward secrecy** — leaking one message key exposes neither
  past nor future messages;
- **break-in recovery** — the DH ratchet rekeys the root every turn, so a
  stolen state snapshot stops working after the next rotation;
- replay/reordering/gap protection (sequence + chainIndex + strict order);
- handshake authentication with long-lived RSA keys;
- key binding to the transcript and to each direction;
- chat identity taken from the JWT, not from client input;
- local pinning (TOFU) of peer identity keys — a later key change from the
  server is rejected until the user explicitly runs `/trust`;
- safety numbers derived from both identity keys for out-of-band comparison
  (`/safety <user>`).

Not provided (see [`SECURITY.md`](../../SECURITY.md)):

- protection against a malicious server on the very first key lookup: TOFU
  trusts the first key, and safety-number comparison is manual, not enforced;
- key transparency (an append-only log) that would verify keys without manual
  comparison;
- skipped-message-key storage and out-of-order tolerance — strict in-order
  delivery is required;
- header encryption (the server can observe sequence numbers and rotation
  cadence);
- JWT revocation and refresh tokens;
- metadata hiding from the server.

---

## 11. Constants

| Parameter | Value |
|-----------|-------|
| E2E version | `3` |
| Ratchet-key flag | `0x01` |
| Ratchet key in frame | raw P-256 point, 65 bytes (`0x04‖X‖Y`) |
| ECDH curve | `secp256r1` (P-256) |
| Identity | RSA ≥ 2048, `SHA256withRSA` |
| Symmetric cipher | AES-256-GCM, 128-bit tag |
| IV | 12 bytes, random per message |
| Chain | HMAC-SHA256: `msg-key`, `next-chain` |
| Rotation | DHKDF: `prk = HMAC(root, dh)`, `…/ratchet/<dir>/{root,chain}` |
| HKDF (handshake) | HMAC-SHA256, salt = SHA-256 transcript |
| Transcript / signatures | SHA-256 / `SHA256withRSA`, label `secure-chat/v3/…` |
| PBKDF2 | HMAC-SHA256, 600,000 iterations, 16-byte salt |
| Key-file format | `SCK1` + salt + IV + ciphertext |
| Min v3 frame length | 46 bytes (111 with ratchet key) |
| Client handshake timeout | 10 seconds |
| Session idle timeout | 30 minutes |
| Session absolute timeout | 24 hours |
| Timestamp tolerance | ±30 seconds |
| Max frame | 96 KiB |
