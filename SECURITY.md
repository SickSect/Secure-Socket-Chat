# Security Design and Threat Model

This document describes how Secure Chat protects messages, which security
properties it actually provides, and which risks remain. It matches the code in
this repository (protocol v2, chat release v0.6).

> **Status:** educational / pre-production. The cryptographic constructions are
> implemented directly and covered by unit tests, but the project has not been
> independently audited. Do not use it for sensitive communications yet.

---

## 1. Scope and trust assumptions

The system has three parties:

| Party | Trust level | Sees |
|-------|-------------|------|
| Client A / Client B | trusted endpoints | plaintext, own private keys |
| Chat server | **honest-but-curious for message content**, trusted for routing and identity lookup | metadata, ciphertext, public keys |
| Network / relay | untrusted | TLS ciphertext only |

TLS protects the client-server hop. End-to-end (E2E) encryption protects the
message body from the server and from anyone who can read server storage. The
server is **not** trusted to keep message contents secret, but it is currently
trusted to return the correct public key for a username. This is the main
residual trust assumption (see [§9](#9-known-limitations-and-residual-risks)).

---

## 2. Key hierarchy

| Key | Algorithm | Lifetime | Purpose |
|-----|-----------|----------|---------|
| Identity key | RSA ≥ 2048, SHA-256 signatures | Long-lived, per user | Authenticates the handshake; public half is stored on the server |
| Identity-key file | PBKDF2-HMAC-SHA256 (600k) + AES-256-GCM | Long-lived, per device | Protects the RSA private key at rest |
| Ephemeral ECDH key | P-256 | One handshake | Produces the shared secret, then is destroyed |
| Directional session keys | AES-256-GCM | One session (idle 30 min / absolute 24 h) | Encrypt messages in each direction |
| Confirmation tags | HKDF-SHA256 output | One handshake | Prove both sides derived the same transcript |
| JWT signing key | HMAC-SHA256, ≥ 32 bytes | Process lifetime or configured | Authenticates REST login tokens |

There is **no static pre-shared key** anymore. Earlier versions encrypted every
client-server frame with a PSK that was committed to the repository; that has
been removed. Transport confidentiality now comes exclusively from TLS 1.3.

---

## 3. End-to-end handshake (protocol v2)

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
4. HKDF-SHA256 derives four independent values from the ECDH secret, using the
   transcript hash as salt and distinct `info` labels:
   `i2r`, `r2i`, `initiator-confirm`, `responder-confirm`.
5. Responder sends its ephemeral public key, signature, and confirmation tag in
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

## 4. Message format and replay protection

Each E2E payload is Base64 of:

```
[version: 1 byte = 0x02][sequence: 8 bytes, big-endian][IV: 12 bytes][AES-GCM ciphertext + 16-byte tag]
```

The GCM additional authenticated data (AAD) is:

```
version || lengthPrefixed(sender) || lengthPrefixed(recipient) || sequence
```

Properties:

- **Directional keys** — `i2r` is only used by the initiator to send and by the
  responder to receive; `r2i` is the reverse. Replaying a frame back to its
  sender fails authentication.
- **Strict sequence numbers** — the receiver accepts only
  `lastReceived + 1`. Replay, reordering, and silently dropped messages are
  rejected. This is the primary anti-replay mechanism.
- **No key reuse across sessions** — keys are bound to the handshake transcript
  (both identities and both ephemeral keys), so a frame from one session cannot
  be decrypted in another.
- **Random 96-bit IV per message** — safe for the number of messages sent under
  one session key.

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

- Registration and login are the only public REST endpoints. The security
  filter chain denies every other path by default.
- Passwords are hashed with BCrypt. Login performs a dummy BCrypt comparison
  for unknown usernames to reduce timing differences.
- JWTs are HMAC-SHA256, issued with a fixed issuer, and validated for
  signature, issuer, expiry, and subject. If `JWT_SECRET` is missing, too short,
  or one of the known public placeholders, the service generates a random
  per-process secret (fail-safe: tokens become invalid on restart).
- The chat server derives the username from the validated JWT, never from a
  client-supplied `JOIN` field. A client cannot claim another user's name.
- Registration rejects malformed or weak RSA keys (minimum 2048 bits, public
  exponent ≥ 65537).
- The public key registered for a username is the one the server returns to
  peers; a client cannot swap its key after registration.
- Auth endpoints are rate-limited per remote address (in-memory token buckets).
- Chat connections have a per-connection command budget (60 commands / 10 s)
  and bounded frame sizes (96 KiB).

---

## 7. Secret storage and memory handling

- Identity private keys are encrypted at rest with PBKDF2-HMAC-SHA256
  (600,000 iterations) + AES-256-GCM. New files start with the `SCK1` magic and
  version marker; legacy files are still readable.
- Key files are written atomically (temp file + rename) and, on filesystems that
  support POSIX permissions, restricted to owner read/write (`0600`).
- Session keys and confirmation tags are wrapped in `DestroyableSecretKey` and
  wiped on expiry, failure, or disconnect (best effort — the JVM may still copy
  arrays).
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

1. **The server is trusted for public-key distribution.** A malicious or
   compromised server can return its own RSA key for Bob, complete a handshake
   with Alice, and relay/re-encrypt messages. The signature scheme prevents
   cross-peer replay but cannot prevent an active key-substitution MITM.
   *Mitigation:* safety numbers / key fingerprints verified out of band,
   key transparency, or pinned identity keys.
2. **No per-message forward secrecy.** Session keys are ephemeral per session
   but reused for up to 30 minutes of idle time / 24 hours absolute. If a
   session key leaks, all messages in that session are exposed. A Double Ratchet
   is not implemented.
3. **No safety numbers.** Users cannot verify that they share the same view of
   each other's identity keys.
4. **No revocation or refresh tokens.** A stolen JWT is valid until it expires
   (default 60 minutes). Logout is client-side only. There is no server-side
   token revocation list.
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
  --tests org.ugina.PbeUtilTest --tests org.ugina.FileBasedKeyStorageTest
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
