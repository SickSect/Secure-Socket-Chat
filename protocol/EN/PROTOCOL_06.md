# Secure Chat — Protocol Specification v2 (v0.6)

Status: current for release **v0.6**.
Previous version: [`PROTOCOL_05.md`](PROTOCOL_05.md).

---

## 1. Overview

Secure Chat uses two independent channels:

1. **REST API over HTTPS** — registration, login, JWT issuance.
2. **TCP chat over TLS 1.3** — JOIN, handshake, message exchange.

Message content is additionally end-to-end encrypted on the clients. The server
sees only metadata and an opaque `e2ePayload`.

Changes in v2 compared with v1:

| v1 | v2 |
|----|----|
| One shared AES key per session | Separate key per direction |
| HKDF with constant `info` | HKDF salted with the SHA-256 handshake transcript |
| No key confirmation | Explicit `SESSION_CONFIRM` / confirmation tags |
| No E2E replay protection | Monotonic sequence number authenticated as AAD |
| Signature covered only the ephemeral key | Signature binds role and both usernames |
| Static PSK transport | TLS 1.3 |

---

## 2. Transport and framing

- REST: HTTPS, TLS 1.3 only, default port `8443`.
- Chat: TLS 1.3, default port `5000`.
- A frame is one UTF-8 line terminated by `\n`; `\r` is ignored.
- Maximum frame length is **96 KiB** on both client and server. Exceeding it
  closes the connection.
- JSON is encoded with Jackson; unknown fields are ignored.
- The client enables TLS hostname verification
  (`endpointIdentificationAlgorithm=HTTPS`) and uses a dedicated truststore
  (`TLS_TRUSTSTORE`).

---

## 3. Authentication (REST)

### POST /api/auth/register

```json
{
  "username": "alice",
  "password": "correct horse battery staple",
  "publicKey": "<Base64 X.509 RSA public key>"
}
```

Constraints:

- `username`: 3–32 characters, `[A-Za-z0-9_]` only.
- `password`: 8–128 characters.
- `publicKey`: valid RSA key of at least 2048 bits, public exponent ≥ 65537.

Response `201 Created`:

```json
{ "status": "registered", "username": "alice" }
```

Errors:

- `400` — validation failure (`VALIDATION_FAILED`).
- `409` — name taken or key rejected (`REGISTRATION_FAILED`).
- `429` — registration rate limit (`RATE_LIMIT_EXCEEDED`).

### POST /api/auth/login

```json
{ "username": "alice", "password": "correct horse battery staple" }
```

Response `200 OK`:

```json
{ "token": "<JWT>", "expiresAt": 1760000000000 }
```

Errors:

- `401` — invalid credentials (`AUTHENTICATION_FAILED`).
- `429` — login rate limit (`RATE_LIMIT_EXCEEDED`).

JWT:

- algorithm HS256;
- issuer `secure-chat`;
- `sub` = username;
- lifetime `JWT_EXPIRATION_MINUTES` (default 60 minutes).

---

## 4. Client → server messages (`ClientMessage`)

All fields are optional; each command uses only the relevant ones.

```json
{
  "commandType": "JOIN",
  "username": "alice",
  "publicKey": "...",
  "toClientName": "bob",
  "e2ePayload": "...",
  "timestamp": 1760000000000,
  "nonce": "...",
  "ephemeralPublicKey": "...",
  "signature": "...",
  "confirmation": "...",
  "jwt": "..."
}
```

| `commandType` | Required fields | Purpose |
|---------------|-----------------|---------|
| `JOIN` | `jwt` | Join chat; username and key are loaded from the DB by token |
| `GET_KEY` | `toClientName` | Fetch a peer's RSA key |
| `INIT_SESSION` | `toClientName`, `ephemeralPublicKey`, `signature` | Start handshake |
| `SESSION_ACK` | `toClientName`, `ephemeralPublicKey`, `signature`, `confirmation` | Answer handshake |
| `SESSION_CONFIRM` | `toClientName`, `confirmation` | Confirm keys |
| `SEND_MESSAGE` | `toClientName`, `e2ePayload`, `timestamp`, `nonce` | Send an E2E message |
| `QUIT` | — | Disconnect |

Field limits:

- `toClientName` — username policy (1–32, `[A-Za-z0-9_]`);
- `nonce` — Base64 of exactly 16 bytes, at most 64 characters;
- `e2ePayload` — non-empty Base64, at most 96 KiB;
- `ephemeralPublicKey` — at most 2 KiB;
- `signature` — at most 2 KiB;
- `confirmation` — at most 512 characters;
- `timestamp` — Unix milliseconds; rejected if it differs by more than 30 seconds.

---

## 5. Server → client messages (`ServerMessage`)

```json
{
  "type": "DM",
  "fromClientName": "bob",
  "e2ePayload": "...",
  "text": "...",
  "errorCode": "INVALID_FORMAT",
  "username": "bob",
  "publicKey": "...",
  "ephemeralPublicKey": "...",
  "signature": "...",
  "confirmation": "..."
}
```

| `type` | Fields | Purpose |
|--------|--------|---------|
| `SYSTEM` | `text` | System message / successful JOIN |
| `DM` | `fromClientName`, `e2ePayload` | Deliver an E2E message |
| `DELIVERED` | — | Server accepted the message |
| `ERROR` | `errorCode`, `text` | Error |
| `PUBLIC_KEY` | `username`, `publicKey` | Response to `GET_KEY` |
| `INIT_SESSION` | `fromClientName`, `ephemeralPublicKey`, `signature` | Forward INIT |
| `SESSION_ACK` | `fromClientName`, `ephemeralPublicKey`, `signature`, `confirmation` | Forward ACK |
| `SESSION_CONFIRM` | `fromClientName`, `confirmation` | Forward CONFIRM |

---

## 6. Handshake v2

Notation:

- `A` — initiator, `B` — responder.
- `ID_A`, `ID_B` — usernames.
- `(E_A, e_A)`, `(E_B, e_B)` — ephemeral P-256 pairs.
- `K` — ECDH shared secret.
- `H` — SHA-256 transcript hash.

### 6.1. Canonical signing payload

```
LABEL = "secure-chat/v2/handshake"
payload = len(LABEL)||LABEL || len(role)||role || len(signer)||signer ||
          len(peer)||peer || len(ephemeralPub)||ephemeralPub
```

`len(x)` is a 4-byte big-endian length; strings are UTF-8.

- Initiator signs `role = "init"`, `signer = ID_A`, `peer = ID_B`,
  `ephemeralPub = E_A`.
- Responder signs `role = "ack"`, `signer = ID_B`, `peer = ID_A`,
  `ephemeralPub = E_B`.

The signature is `SHA256withRSA` under the identity key. Binding the role and
both usernames prevents a captured INIT from being replayed to another peer or
in the opposite direction.

### 6.2. Transcript and key derivation

```
transcript = len("secure-chat/v2/transcript") ||
             len(ID_A) || len(ID_B) || len(E_A) || len(E_B)

H = SHA-256(transcript)
```

HKDF-SHA256:

```
i2r               = HKDF(K, salt = H, info = "secure-chat/v2/i2r",               32)
r2i               = HKDF(K, salt = H, info = "secure-chat/v2/r2i",               32)
initiator-confirm = HKDF(K, salt = H, info = "secure-chat/v2/initiator-confirm", 32)
responder-confirm = HKDF(K, salt = H, info = "secure-chat/v2/responder-confirm", 32)
```

Directions:

- `A` encrypts with `i2r`, decrypts with `r2i`;
- `B` encrypts with `r2i`, decrypts with `i2r`.

### 6.3. Sequence

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
|-- SEND_MESSAGE(bob, seq=0, ...) ----->|-- DM(alice, seq=0, ...) ------------>|
```

Steps:

1. `A` fetches `rsaB`, generates `(E_A, e_A)`, signs the payload, and sends
   `INIT_SESSION`.
2. `B` verifies `A`'s signature with `rsaA` (obtained via `GET_KEY`).
3. `B` generates `(E_B, e_B)`, computes `K`, `H`, and the keys, signs with
   `role="ack"`, computes `conf_B`, and sends `SESSION_ACK`.
4. `A` verifies `B`'s signature, computes `K`, `H`, and the keys, and compares
   `conf_B` in constant time. On success it sends `SESSION_CONFIRM` with
   `conf_A`, then marks the session `READY`.
5. `B` compares `conf_A` in constant time and only then marks the session
   `READY`.

The session cannot carry messages before confirmation completes.

### 6.4. Simultaneous handshake

If `A` and `B` start a handshake at the same time, a deterministic rule applies:
the lexicographically smaller username keeps the initiator role. The other side
destroys its pending context and answers as responder. This prevents the two
contexts from overwriting each other.

---

## 7. E2E message format

`e2ePayload` is Base64 of:

```
+--------+------------------+------------+----------------------------+
| ver(1) | sequence(8, BE)  | IV(12)     | AES-256-GCM ciphertext+tag |
+--------+------------------+------------+----------------------------+
```

AAD:

```
ver || len(sender)||sender || len(recipient)||recipient || sequence(8, BE)
```

Receive rules:

1. Length ≥ 1 + 8 + 12 + 16 bytes.
2. `ver == 2`.
3. `sequence == lastReceived + 1` (strict, no gaps).
4. GCM tag must verify.

The receive counter advances only after successful decryption. This rejects
replay, reordering, and injected frames. The send counter starts at 0 and
increments by 1 per message.

The `nonce` and `timestamp` in `SEND_MESSAGE` are an additional coarse
server-side check (a `(sender, nonce)` cache for 60 seconds and ±30 seconds of
clock skew). The primary integrity protection is the sequence number in the E2E
envelope.

---

## 8. Session lifecycle

- `WAITING_FOR_ACK` — initiator sent INIT.
- `WAITING_FOR_CONFIRM` — responder sent ACK and waits for CONFIRM.
- `READY` — keys confirmed, messages allowed.
- `FAILED` — handshake rejected or destroyed.

Timeouts:

- idle — 30 minutes without activity;
- absolute — 24 hours since creation.

On expiry the session is destroyed with its keys, and the next message starts a
new handshake. On disconnect all sessions are destroyed.

Server:

- connection idle timeout — 30 minutes;
- command budget — 60 commands per 10 seconds per connection;
- thread pool — 8–64 threads, queue 256; connections are rejected when full;
- one connection per username at a time.

---

## 9. Error codes

| Code | Meaning |
|------|---------|
| `INVALID_NAME` | Invalid username |
| `NAME_TAKEN` | Username already connected |
| `INVALID_PUBLIC_KEY` | Invalid or weak public key |
| `RECIPIENT_OFFLINE` | Recipient not connected / not found |
| `EXPIRED` | Stale timestamp |
| `REPLAY` | Duplicate nonce |
| `DECRYPTION_FAILED` | Decryption failure |
| `INVALID_FORMAT` | Malformed JSON/fields/size |
| `RATE_LIMITED` | Command limit exceeded |
| `INTERNAL_ERROR` | Internal error |
| `INVALID_TOKEN` | JWT missing, expired, or invalid |

---

## 10. Security properties

Provided:

- content confidentiality from the server and the network (E2E + TLS);
- message integrity and authenticity (GCM + AAD);
- replay/reordering protection within a session;
- per-session forward secrecy (ephemeral ECDH keys are destroyed);
- handshake authentication with long-lived RSA keys;
- key binding to the transcript and to each direction;
- chat identity taken from the JWT, not from client input.

Not provided (see [`SECURITY.md`](../../SECURITY.md)):

- protection against an active malicious server that substitutes public keys;
- per-message forward secrecy;
- safety numbers / fingerprint verification;
- JWT revocation and refresh tokens;
- metadata hiding from the server.

---

## 11. Constants

| Parameter | Value |
|-----------|-------|
| E2E version | `2` |
| ECDH curve | `secp256r1` (P-256) |
| Identity | RSA ≥ 2048, `SHA256withRSA` |
| Symmetric cipher | AES-256-GCM, 128-bit tag |
| IV | 12 bytes, random per message |
| HKDF | HMAC-SHA256 |
| Transcript | SHA-256 |
| PBKDF2 | HMAC-SHA256, 600,000 iterations, 16-byte salt |
| Key-file format | `SCK1` + salt + IV + ciphertext |
| Client handshake timeout | 10 seconds |
| Session idle timeout | 30 minutes |
| Session absolute timeout | 24 hours |
| Timestamp tolerance | ±30 seconds |
| Maximum frame | 96 KiB |
