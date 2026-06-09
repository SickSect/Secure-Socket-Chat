# Secure Chat Protocol Specification

**Version:** 0.4 (Draft)
**Status:** In development
**Date:** 2026-05-20

---

## 1. Overview

Secure Chat Protocol (SCP) is an application-layer protocol over TCP for
exchanging messages between multiple clients through a central server.

Version 0.4 introduces **forward secrecy** via ephemeral ECDH keys and
**persistent identity** via password-protected storage of long-lived
RSA keys. Message content is no longer encrypted with a long-lived key —
compromising the identity key does not reveal past sessions.

### v0.4 Features

- **Persistent identity** — client RSA keys are preserved between sessions
  in a password-protected file (PBKDF2 + AES-GCM)
- **Forward secrecy** via session-level ephemeral ECDH keys
- **Handshake authentication** — ephemeral ECDH keys are signed with the
  long-lived RSA key; the peer verifies the signature
- **Session keys** — message content is encrypted with AES-GCM using a key
  derived from the ECDH secret via HKDF
- RSA in v0.4 is used **only for signatures**, not for encryption

### Change in RSA's Role

In v0.3, RSA encrypted per-message AES keys (Hybrid scheme). In v0.4 this
scheme is replaced: RSA is used only to sign ephemeral ECDH keys during
the handshake. Messages themselves are encrypted with `session_key`,
which is derived through ECDH+HKDF and is independent of RSA keys.

---

## 2. Architecture

The protocol has three layers of protection:

### Layer 1: Transport channel (PSK)

All messages between client and server are encrypted with a shared
pre-shared key (AES-256-GCM). Protects metadata (commands, names) from
passive eavesdropping by network providers.

### Layer 2: Identity keys (RSA-2048)

Long-lived RSA keys of clients. Used for:
- Signing ephemeral ECDH keys during handshake
- Proving client identity

Persisted between client launches in a password-protected file.

### Layer 3: Session keys (AES-256)

Symmetric session keys derived via ECDH+HKDF between two specific clients.
Encrypt message content. Exist only in memory; destroyed when the session
ends.

---

## 3. Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|-----------|
| Transport encryption | AES-GCM | 256-bit key, 96-bit IV, 128-bit tag |
| Identity keys | RSA | 2048-bit, X.509 / PKCS#8 |
| Identity signatures | RSA-PKCS#1 v1.5 | SHA256withRSA |
| Ephemeral keys | ECDH | curve secp256r1 (P-256) |
| Key derivation (from password) | PBKDF2 | HMAC-SHA256, 100,000 iterations |
| Key derivation (from ECDH secret) | HKDF | HMAC-SHA256, RFC 5869 |
| Message encryption | AES-GCM | session_key (256-bit), 96-bit IV |

---

## 4. Connection Lifecycle

### 4.1 Identity setup (one-time, per username)

1. User launches the client, enters username and password
2. Client checks the file `~/.secure-chat/<username>.key`
3. If the file exists — decrypts the private key with the password
4. If no file — generates a new RSA pair and saves it
5. File format:
   ```
   [public_key_length 4B big-endian]
   [public_key X.509 encoded]
   [PBE-encrypted private_key (PKCS#8)]
   ```
6. PBE-encrypted private_key:
   ```
   [salt 16B] [iv 12B] [ciphertext + auth_tag 16B]
   ```

### 4.2 Server handshake

1. Client opens a TCP connection to the server (default port 5000)
2. Client sends `JOIN` with username and public RSA key
3. Server registers the client in its registry
4. Server responds with `SYSTEM` (welcome) or `ERROR` (`NAME_TAKEN`)
5. Client is ready to exchange messages

### 4.3 Session handshake (new in v0.4)

A handshake is initiated when sending the first message to a peer:

**1. Initiator (Alice → Bob):**
- Obtains Bob's RSA public key (via `GET_KEY` if not cached)
- Generates ephemeral ECDH pair `(eph_a_priv, eph_a_pub)`
- Signs `eph_a_pub` with the long-lived RSA private key
- Sends `INIT_SESSION` with `eph_a_pub` and signature
- Waits for `SESSION_ACK` (10-second timeout)

**2. Recipient (Bob):**
- Receives `INIT_SESSION` from server
- Obtains Alice's RSA public key (if not cached)
- Verifies Alice's signature; if invalid — ignores the request
- Generates own ephemeral ECDH pair `(eph_b_priv, eph_b_pub)`
- Computes `shared_secret = ECDH(eph_b_priv, eph_a_pub)`
- Derives `session_key = HKDF(shared_secret, "secure-chat-session", 32)`
- Destroys `eph_b_priv` (forward secrecy)
- Signs `eph_b_pub` with the long-lived RSA private key
- Sends `SESSION_ACK` with `eph_b_pub` and signature

**3. Completion at initiator:**
- Alice receives `SESSION_ACK`
- Verifies Bob's signature
- Computes `shared_secret = ECDH(eph_a_priv, eph_b_pub)`
- Derives the same `session_key`
- Destroys `eph_a_priv`

After the handshake, both parties hold the same `session_key`. Ephemeral
private keys are destroyed. The session is in the READY state.

### 4.4 Message exchange

After session establishment:
1. Sender encrypts plaintext with AES-GCM using `session_key`
2. Forms `SEND_MESSAGE` with e2ePayload, timestamp, nonce
3. Server validates timestamp (≤ 30 seconds) and nonce (replay protection)
4. Server forwards DM to the recipient
5. Recipient decrypts with `session_key` from their `SessionContext`

### 4.5 Termination

1. Client sends `QUIT` or closes the connection
2. Server removes the client from the registry
3. Ephemeral session data in process memory is lost on JVM exit

---

## 5. Message Formats

All messages are serialized to JSON via Jackson and encrypted with the PSK.

### 5.1 Client → Server messages

#### JOIN
```json
{
  "commandType": "JOIN",
  "username": "alice",
  "publicKey": "<Base64 X.509 RSA public key>"
}
```

#### GET_KEY
```json
{
  "commandType": "GET_KEY",
  "toClientName": "bob"
}
```

#### INIT_SESSION (new in v0.4)
```json
{
  "commandType": "INIT_SESSION",
  "toClientName": "bob",
  "ephemeralPublicKey": "<Base64 X.509 ECDH public key>",
  "signature": "<Base64 RSA signature of ephemeralPublicKey bytes>"
}
```

#### SESSION_ACK (new in v0.4)
```json
{
  "commandType": "SESSION_ACK",
  "toClientName": "alice",
  "ephemeralPublicKey": "<Base64 X.509 ECDH public key>",
  "signature": "<Base64 RSA signature of ephemeralPublicKey bytes>"
}
```

#### SEND_MESSAGE
```json
{
  "commandType": "SEND_MESSAGE",
  "toClientName": "bob",
  "e2ePayload": "<Base64 AES-GCM ciphertext with session_key>",
  "timestamp": 1747130400000,
  "nonce": "<Base64 16 random bytes>"
}
```

#### QUIT
```json
{
  "commandType": "QUIT"
}
```

### 5.2 Server → Client messages

#### DM
```json
{
  "type": "DM",
  "fromClientName": "alice",
  "e2ePayload": "<Base64 AES-GCM ciphertext>"
}
```

#### DELIVERED
```json
{
  "type": "DELIVERED"
}
```

#### PUBLIC_KEY
```json
{
  "type": "PUBLIC_KEY",
  "username": "bob",
  "publicKey": "<Base64 X.509 RSA public key>"
}
```

#### INIT_SESSION (forwarded)
```json
{
  "type": "INIT_SESSION",
  "fromClientName": "alice",
  "ephemeralPublicKey": "<Base64>",
  "signature": "<Base64>"
}
```

#### SESSION_ACK (forwarded)
```json
{
  "type": "SESSION_ACK",
  "fromClientName": "bob",
  "ephemeralPublicKey": "<Base64>",
  "signature": "<Base64>"
}
```

#### ERROR
```json
{
  "type": "ERROR",
  "errorCode": "<see error codes>",
  "text": "human-readable description"
}
```

#### SYSTEM
```json
{
  "type": "SYSTEM",
  "text": "Welcome, alice"
}
```

---

## 6. Error Codes

| Code | Description |
|------|-------------|
| `INVALID_NAME` | Username does not meet requirements |
| `NAME_TAKEN` | Username is already in use by another client |
| `INVALID_PUBLIC_KEY` | Public key cannot be parsed |
| `RECIPIENT_OFFLINE` | Recipient is not connected |
| `EXPIRED` | Message is older than 30 seconds |
| `REPLAY` | Nonce has already been seen |
| `DECRYPTION_FAILED` | Decryption failed |
| `INVALID_FORMAT` | Invalid message format |
| `INTERNAL_ERROR` | Internal server error |

---

## 7. Server Responsibilities

The server performs **routing only**:
- Client registration
- Maintaining the registry: `name → handler, publicKey`
- Validating `timestamp` and `nonce` for replay protection
- Forwarding `INIT_SESSION`, `SESSION_ACK`, and DM byte-for-byte
- Returning errors to initiators for invalid operations

The server **has no access to**:
- Message contents (encrypted with `session_key`)
- `session_key` (no ECDH private keys held)
- Ephemeral private keys

---

## 8. Threat Model

### Mitigated Threats

**Passive eavesdropping by network provider** (mitigated by PSK):
- Attacker sees TCP packets but cannot read JSON metadata

**Server compromise** (mitigated by E2E + forward secrecy):
- Attacker with server access cannot read message contents
- Attacker cannot impersonate clients (no private keys)

**MITM during handshake** (mitigated by RSA signatures):
- Attacker tries to substitute the ephemeral key in INIT_SESSION/SESSION_ACK
- Recipient verifies the signature with the long-lived RSA public key
- Forging the signature is infeasible without the sender's private key

**Replay attacks** (mitigated by timestamp + nonce):
- Attacker replays an old captured packet
- Server rejects: either timestamp is expired (>30 sec) or nonce is reused

**Future compromise of identity keys** (mitigated by forward secrecy):
- If Alice's long-lived RSA private key is stolen tomorrow
- Past sessions remain protected
- Ephemeral private keys have been destroyed long ago and cannot be recovered

### Unmitigated Threats (known limitations)

**Client device compromise:**
- Attacker with access to client process memory sees the current
  `session_key` and the long-lived RSA private key
- OS-level protection (process isolation) is out of scope for the protocol

**Per-message forward secrecy:**
- v0.4 provides forward secrecy at the **session** level, not per message
- Compromise of `session_key` exposes all messages in that session
- Per-message FS (Double Ratchet as in Signal) — planned for v0.5+

**Metadata under server compromise:**
- Server sees who messages whom and when
- Does not see content, but contact graphs are exposed
- Protection against metadata leakage requires more advanced protocols
  (e.g., mix networks)

**Swap file / memory dump leaks:**
- `session_key` and private keys may end up in swap or memory dumps
- v0.4 does not explicitly zeroize memory (`Arrays.fill`)
- Planned for v0.5+

**Denial of service (DoS):**
- Server has no rate limiting
- Attacker can flood the server with handshake requests
- Planned: per-IP rate limiting in v0.5+

**Identity key authentication:**
- On first contact, the client trusts the public key returned by the server
  via `GET_KEY` (TOFU — trust on first use)
- Security risk: the server could substitute the key on first delivery
- Verification codes / safety numbers — planned for v0.6+

---

## 9. Cryptographic Constants

```
PSK_KEY_SIZE        = 256 bit
RSA_KEY_SIZE        = 2048 bit
ECDH_CURVE          = secp256r1 (P-256)
AES_IV_SIZE         = 12 bytes
AES_TAG_SIZE        = 16 bytes
NONCE_SIZE          = 16 bytes
TIMESTAMP_WINDOW    = 30,000 ms
NONCE_TTL           = 60,000 ms

PBKDF2_ITERATIONS   = 100,000
PBKDF2_SALT_SIZE    = 16 bytes
PBKDF2_KEY_SIZE     = 256 bit

HKDF_INFO           = "secure-chat-session"
HKDF_OUTPUT_SIZE    = 32 bytes
SESSION_HANDSHAKE_TIMEOUT = 10,000 ms
```

---

## 10. Backwards Compatibility

v0.4 is **not compatible** with v0.3:
- v0.3 clients encrypt messages via HybridCrypto (RSA+AES)
- v0.4 clients encrypt via `session_key` (AES-GCM)
- Cross-version decryption is impossible

Future versions may support version negotiation during JOIN.

---

## 11. Roadmap

**v0.5:**
- User registration in a database
- JWT authentication
- Rate limiting
- Zeroize `session_key` in memory on session end

**v0.6:**
- Verification codes / safety numbers
- Protection against MITM at first key exchange

**v0.7:**
- WebSocket transport
- Web client
- Multiple device support

**v1.0:**
- Persistent message history
- Offline message delivery
- Presence (online/offline status)

**Backlog:**
- Per-message forward secrecy (Double Ratchet)
- Group chat (MLS)
- Platform-specific KeyStorage (Windows Credential Manager, etc.)
- Maven Central SDK
- Migration from SHA256withRSA to Ed25519 for signatures

---

## 12. References

- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HKDF
- [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) — PKCS #5 (PBKDF2)
- [SEC 2](https://www.secg.org/sec2-v2.pdf) — Recommended Elliptic Curve Parameters (secp256r1)
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) — AES-GCM
- [Signal Protocol](https://signal.org/docs/) — inspiration for forward secrecy design