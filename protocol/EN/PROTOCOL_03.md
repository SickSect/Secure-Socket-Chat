# Secure Chat Protocol Specification

**Version:** 0.3 (Draft)
**Status:** In development
**Date:** 2026-05-13

---

## 1. Overview

Secure Chat Protocol (SCP) is an application-layer protocol over TCP for
exchanging messages between multiple clients through a central server.

Version 0.3 introduces **end-to-end encryption** via a hybrid RSA+AES scheme
and replay-attack protection. The channel encryption from v0.2 remains as
an outer layer.

### v0.3 capabilities

- Client connection by name with structured handshake
- Registration of client's RSA public key on the server
- Retrieval of another client's public key through the server
- **End-to-end message encryption** — the server cannot read message content
- **Replay-attack protection** via timestamp + nonce-tracking
- Outer channel encryption via AES-PSK (carried over from v0.2)
- Unified JSON format in both directions

### Encryption layers

```
┌─────────────────────────────────────────────────────────────┐
│  PSK AES-GCM (transport layer)                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  JSON: { commandType, ..., e2ePayload: "..." }        │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  HybridCrypto (E2E): RSA(AES-key)+AES(msg)      │  │  │
│  │  │  ┌──────────────────────────────────────────┐   │  │  │
│  │  │  │  Plaintext message                       │   │  │  │
│  │  │  └──────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

The outer layer (PSK) protects against passive network eavesdropping.
The inner layer (E2E) protects against reading by the server.

### v0.3 limitations

- **No public-key verification.** The server distributes a peer's key without
  any way to verify its authenticity. A compromised server can substitute the
  key (MITM attack on E2E). Solution — verification codes — in v0.6+.
- **No forward secrecy.** If a private key is compromised, past messages can be
  decrypted. Solved via ephemeral keys or Double Ratchet.
- **Private key in memory only.** Each client launch generates a new key pair.
  Persistence is planned for v0.4.
- **Server sees metadata.** Who, whom, when. Protection requires mix-networks.
- **Single shared PSK for the channel.** Knowing the PSK = permission to connect.
  Client authentication via JWT — in v0.5.
- Messages are not stored: if the recipient is offline, the message is lost.

---

## 2. Transport

| Parameter | Value |
|-----------|-------|
| Transport protocol | TCP |
| Default port | 5000 |
| Encoding | UTF-8 |
| Message delimiter | `\n` (LF) |
| Model | Client-server, one server per N clients |

Each message is a single line terminated by `\n`.
The line content is a Base64-encoded ciphertext of the PSK layer.

---

## 3. Cryptography

### 3.1. Symmetric (transport layer)

- **Cipher:** AES in GCM mode
- **Key size:** 256 bit
- **IV size:** 96 bit (12 bytes)
- **Auth tag:** 128 bit (16 bytes)
- **Java cipher string:** `AES/GCM/NoPadding`

The PSK key is loaded from `application.properties` or the `SCP_PSK`
environment variable. It is identical on the server and all clients.

### 3.2. Asymmetric (E2E layer)

- **Cipher:** RSA
- **Key size:** 2048 bit
- **Padding:** OAEP with SHA-256 and MGF1
- **Java cipher string:** `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

Each client generates its own key pair on startup. The public key is sent to
the server in JOIN. The private key **never leaves the client**.

### 3.3. Hybrid encryption (E2E messages)

For each message sent to a specific recipient:

1. Generate a one-time AES-256 key via `KeyGenerator`
2. Encrypt the plaintext with AES-GCM using this key → `aesPayload`
3. Encrypt the AES key with RSA using the recipient's public key → `rsaKey`
4. Concatenate: `payload = rsaKey (256B) || aesPayload`
5. Encode in Base64

Recipient:

1. Decode Base64 → payload bytes
2. First 256 bytes → `rsaKey` (encrypted AES key)
3. Remainder → `aesPayload` (encrypted message)
4. Decrypt `rsaKey` with RSA using own private key → AES key
5. Decrypt `aesPayload` with AES-GCM using this key → plaintext

### 3.4. Replay protection

Every `SEND_MESSAGE` contains:

- `timestamp` — Unix epoch in milliseconds
- `nonce` — 16 random bytes in Base64

The server verifies:

- `|now - timestamp| < 30 seconds` — otherwise `ERROR: EXPIRED`
- `nonce` has not been seen in the last 60 seconds — otherwise `ERROR: REPLAY`

The server stores nonces in `ConcurrentHashMap<String, Long>` (nonce → expiration).
Stale entries are cleaned up by a background task once per minute.

### 3.5. Security guarantees

| Threat | Protection in v0.3 |
|--------|--------------------|
| Passive network eavesdropping | ✅ PSK AES-GCM |
| Ciphertext tampering | ✅ GCM auth tag (both layers) |
| Server reading content | ✅ E2E via RSA+AES |
| Replay attack | ✅ timestamp + nonce-tracking |
| Sender spoofing | ✅ Server uses handler context |
| MITM during key distribution | ❌ Solved in v0.6+ |
| Private key compromise | ❌ Forward secrecy in future |
| DDoS on server | ❌ Rate limiting in v0.5+ |
| Metadata analysis by server | ❌ Out of scope |

---

## 4. Wire format

### 4.1. Outer layer (PSK)

```
Base64( IV (12B) || ciphertext (N) || authTag (16B) ) \n
```

After Base64-decoding and AES-GCM decryption, the inner content is a JSON message.

### 4.2. E2E payload (inside SEND_MESSAGE)

```
Base64( RSA_encrypted_AES_key (256B) || AES_encrypted_message (N) )
```

Transmitted as the string field `e2ePayload` inside JSON.

---

## 5. JSON Message Schema

### 5.1. Client → Server (ClientMessage)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `commandType` | enum | yes | `JOIN`, `SEND_MESSAGE`, `GET_KEY`, `QUIT` |
| `username` | string | for JOIN | User name |
| `publicKey` | string | for JOIN | RSA public key in Base64 (X.509) |
| `toClientName` | string | for SEND_MESSAGE, GET_KEY | Target name |
| `e2ePayload` | string | for SEND_MESSAGE | E2E-encrypted message in Base64 |
| `timestamp` | long | for SEND_MESSAGE | Unix epoch ms |
| `nonce` | string | for SEND_MESSAGE | 16 random bytes in Base64 |

**Changes from v0.2:**
- Added `publicKey` to JOIN
- Added `commandType: GET_KEY`
- In SEND_MESSAGE, field `message` replaced by `e2ePayload`
- In SEND_MESSAGE, added `timestamp` and `nonce`

### 5.2. Server → Client (ServerMessage)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `messageType` | enum | yes | `DM`, `DELIVERED`, `ERROR`, `SYSTEM`, `PUBLIC_KEY` |
| `fromClientName` | string | for DM | Sender's name |
| `e2ePayload` | string | for DM | Encrypted message (unchanged) |
| `text` | string | for SYSTEM, ERROR | Text to display |
| `errorCode` | enum | for ERROR | Error code |
| `username` | string | for PUBLIC_KEY | Name of the client whose key it is |
| `publicKey` | string | for PUBLIC_KEY | RSA public key in Base64 |

**Changes from v0.2:**
- Added `messageType: PUBLIC_KEY`
- In DM, field `text` replaced by `e2ePayload`

---

## 6. Commands

### 6.1. JOIN

**Direction:** client → server
**When:** first message after TCP connection is established

```json
{
  "commandType": "JOIN",
  "username": "Alice",
  "publicKey": "MIIBIjANBgkqhkiG9w0B..."
}
```

**Server behavior:**

1. Validate `username` (see §8)
2. Verify the name is not taken
3. Parse `publicKey` (Base64 → X.509 → RSAPublicKey)
4. Register: name → handler, name → publicKey
5. Send `SYSTEM` with a greeting

**Errors:** `INVALID_NAME`, `NAME_TAKEN`, `INVALID_PUBLIC_KEY`

### 6.2. GET_KEY

**Direction:** client → server
**When:** before sending the first message to a peer

```json
{
  "commandType": "GET_KEY",
  "toClientName": "Bob"
}
```

**Server behavior:**

1. Look up `Bob` in the public-key registry
2. If found → `PUBLIC_KEY` with username, publicKey
3. If not → `ERROR: RECIPIENT_OFFLINE`

The client caches the received key locally to avoid repeated requests.

### 6.3. SEND_MESSAGE

```json
{
  "commandType": "SEND_MESSAGE",
  "toClientName": "Bob",
  "e2ePayload": "base64-hybrid-encrypted",
  "timestamp": 1747130400000,
  "nonce": "base64-16-random-bytes"
}
```

**Server behavior:**

1. Check replay protection:
    - `|now - timestamp| < 30000ms` otherwise `ERROR: EXPIRED`
    - `nonce` not in cache otherwise `ERROR: REPLAY`
    - Add `nonce` to cache with TTL 60 sec
2. Find recipient
3. If found → forward `DM` with `e2ePayload` **unchanged**
4. To sender → `DELIVERED`
5. If not found → `ERROR: RECIPIENT_OFFLINE`

**Important:** `fromClientName` is taken from the handler context, not from JSON
— protection against spoofing. The server **does not decrypt** `e2ePayload`.

### 6.4. QUIT

```json
{"commandType": "QUIT"}
```

Remove from the connected registry and from the key registry, close the connection.

---

## 7. Error codes

| errorCode | When |
|-----------|------|
| `INVALID_NAME` | Name failed validation |
| `NAME_TAKEN` | Name already in use |
| `INVALID_PUBLIC_KEY` | Public key does not parse |
| `RECIPIENT_OFFLINE` | Recipient not connected |
| `EXPIRED` | Timestamp outside allowed window |
| `REPLAY` | Nonce already seen |
| `DECRYPTION_FAILED` | PSK-layer decryption failed |
| `INVALID_FORMAT` | JSON does not parse |
| `INTERNAL_ERROR` | Server-side error |

---

## 8. Name validation

- Length: 1–32 UTF-8 characters
- Allowed: Latin, Cyrillic, digits, `_`, `-`
- Regex: `^[\p{L}\p{N}_-]{1,32}$`
- Cannot start with `_` or `-`

---

## 9. Connection lifecycle

```
CLIENT                                        SERVER
  |                                             |
  |--- TCP connect ---------------------------->|
  |                                             |  accept, new Handler
  |  [generate RSA keypair]                     |
  |--- enc_psk(JOIN, name, publicKey) --------->|
  |                                             |  validate, register
  |<-- enc_psk(SYSTEM, "welcome") --------------|
  |                                             |
  |--- enc_psk(GET_KEY, "Bob") ---------------->|
  |<-- enc_psk(PUBLIC_KEY, "Bob", <key>) -------|
  |  [cache Bob's key]                          |
  |  [encrypt msg via HybridCrypto]             |
  |--- enc_psk(SEND_MESSAGE, ...) ------------->|
  |                                             |  check ts + nonce
  |<-- enc_psk(DELIVERED) ----------------------|
  |                                             |--- enc_psk(DM, ...) --> Bob
  |                                             |
  |--- enc_psk(QUIT) -------------------------->|
  |                                             |  unregister
```

`enc_psk(...)` denotes AES-GCM encryption with the PSK per §3.1.

---

## 10. Privacy properties (Threat Model)

### Against passive network eavesdropping

- Content: ✅ protected (double encryption)
- Metadata: ✅ protected by PSK layer
- Fact of communication with the server: ❌ visible

### Against active network MITM

- Content: ✅ protected (GCM auth tag)
- Packet substitution: ✅ detectable

### Against a malicious server

- Content: ✅ protected by E2E
- Metadata (who/whom/when): ❌ server sees everything
- Public-key substitution: ❌ possible (solved in v0.6+)

### Against client compromise

- Peer messages: ✅ protected
- Past own messages: ❌ decryptable (no forward secrecy)

---

## 11. Backward compatibility

v0.3 is not compatible with v0.2.

---

## 12. Versioning roadmap

| Version | Status | Changes |
|---------|--------|---------|
| v0.1 | ✅ Done | Basic TCP chat without encryption |
| v0.2 | ✅ Done | AES-GCM channel encryption, JSON protocol |
| **v0.3** | **🚧 In progress** | **E2E via RSA+AES, replay protection** |
| v0.4 | Planned | Persistent key storage, forward secrecy |
| v0.5 | Planned | JWT authentication, rate limiting |
| v0.6 | Planned | Key verification, trust-on-first-use |
| v0.7 | Planned | WebSocket, web client |
| v1.0 | Planned | History, offline delivery, presence |

---

## 13. Known issues and limitations (v0.3)

1. **MITM during public-key distribution.** Server may substitute keys.
2. **No forward secrecy.** Key compromise compromises the past.
3. **Private key is not persisted.** Each launch generates a new pair.
4. **Server sees metadata.** Who, whom, when.
5. **Single shared PSK.** Anyone with the PSK can connect.
6. **Nonce cache in memory.** Server restart resets replay protection for one minute.
7. **Messages are lost** when the recipient is offline.
8. **No authentication.** Any free name can be used to connect.