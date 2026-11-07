# Secure Chat

A TCP-based end-to-end encrypted chat built from scratch in Java, focused on
understanding cryptographic primitives directly rather than relying on high-level
libraries.

The current release (**v0.7**) adds **per-message forward secrecy** to the
end-to-end core: message protocol v3 with one-way HMAC chains and a DH ratchet.
Earlier releases hardened the deployment around it: TLS 1.3 everywhere, a
transcript-bound handshake with explicit key confirmation, strict message
sequence numbers, JWT-authenticated chat access, PostgreSQL-backed users, and
fail-closed configuration.

> **Security documentation** — threat model, key hierarchy, and residual risks
> are documented in [`SECURITY.md`](SECURITY.md). The full protocol
> specification is in [`protocol/EN/PROTOCOL_07.md`](protocol/EN/PROTOCOL_07.md)
> (Russian: [`protocol/RU/PROTOCOL_07.md`](protocol/RU/PROTOCOL_07.md)).
>
> **Beginner's guide** (Russian) — every algorithm's role, code examples from
> this repository, the key hierarchy and the life of one message:
> [`CRYPTO_GUIDE_RU.md`](CRYPTO_GUIDE_RU.md).
>
> **Auth guide** (Russian) — access/refresh tokens, rotation, session
> revocation: [`AUTH_GUIDE_RU.md`](AUTH_GUIDE_RU.md).

---

## Features

- **End-to-end encryption** — message content is encrypted with directional
  AES-256-GCM session keys. The server only routes ciphertext and cannot read
  messages.
- **Forward secrecy per session** — session keys are derived from ephemeral ECDH
  (P-256) key pairs that are destroyed after the handshake.
- **Per-message forward secrecy** — every message is encrypted with a fresh key
  from a one-way HMAC chain, so leaking one key exposes exactly one message.
  The DH ratchet rekeys the root every round trip, so even a stolen session
  snapshot stops working after the next rotation (break-in recovery).
- **Transcript-bound key derivation** — HKDF-SHA256 uses the full handshake
  transcript (both identities and both ephemeral keys) as salt, so keys cannot
  be reused across peers or sessions.
- **Explicit key confirmation** — both sides prove they derived the same keys
  before the session becomes usable.
- **Replay and reordering protection** — every E2E payload carries a monotonic
  sequence number authenticated as GCM AAD.
- **Authenticated handshake** — ephemeral keys are signed with the long-lived
  RSA-2048 identity key; the signature binds the role and both usernames.
- **Peer key verification** — the first public key seen for a peer is pinned
  locally (TOFU), and a later key change blocks the handshake until an explicit
  `/trust`. `/safety <user>` shows a safety number to compare over a separate
  channel, which detects server-side key substitution.
- **Persistent identity** — each user has a long-lived RSA key pair stored
  locally in a password-protected file (PBKDF2 600k + AES-GCM).
- **TLS 1.3 transport** — both REST (HTTPS) and the chat TCP port use TLS 1.3;
  the old static pre-shared key has been removed.
- **JWT authentication** — registration and login over REST; the chat identity
  is taken from the validated token, not from client claims.
- **Session revocation** — short-lived access tokens (10 minutes) plus
  single-use refresh tokens with rotation and reuse detection; `/logout`
  immediately revokes **every** outstanding token of the user
  (`token_version`), chat `JOIN` included.
- **Session lifecycle** — sessions expire on idle timeout or absolute age,
  triggering a fresh handshake (key rotation) on the next message.
- **Key zeroization** — session keys and confirmation tags are overwritten on
  expiry, disconnect, or exit (best effort on the JVM).
- **Hardened defaults** — default-deny HTTP authorization, bounded frames and
  thread pools, rate limiting, validated RSA/EC keys, no stack traces in errors.

---

## Tech Stack

- **Java 23**
- **Spring Boot** — REST endpoints, dependency injection, configuration
- **Spring Security** — BCrypt password hashing, default-deny filter chain
- **PostgreSQL** + **Flyway** — user persistence and schema migrations
- **JJWT** — JSON Web Token issuance and validation
- **Gradle** — build tooling
- **TestNG** — testing
- **TLS 1.3** — HTTPS REST API and the chat transport
- Raw TCP sockets for the chat transport (no WebSocket/STOMP — intentional, to
  work with the protocol directly)

---

## Quick Start

### Prerequisites

- JDK 23+
- PostgreSQL 16+ (database named `secure_chat`)

### 1. Configure the environment

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set at least:

- `DB_PASSWORD` — your PostgreSQL password
- `JWT_SECRET` — a random value of at least 32 bytes (leave empty only for a
  throwaway local run; tokens then reset on every restart)
- `JWT_EXPIRATION_MINUTES` — access-token TTL (default10 minutes); long-lived
  sessions are served by refresh tokens (`REFRESH_TOKEN_DAYS`, default30 days,
  single-use — rotated on every `/refresh`)
- `TLS_KEYSTORE_PASSWORD` / `TLS_KEY_PASSWORD` / `TLS_TRUSTSTORE_PASSWORD`

The Gradle build loads `.env` automatically for `bootRun`, `runServer`,
`runClient`, and `test`. Spring Boot itself does not read `.env`; if you run the
JAR directly, export the variables in your shell or IDE.

### 2. Generate development TLS certificates

```powershell
powershell -ExecutionPolicy Bypass -File certs/generate-dev-certs.ps1
```

This creates `certs/server-keystore.p12`, `certs/server.crt`, and
`certs/client-truststore.p12` (all gitignored). See
[`certs/README.md`](certs/README.md) for details.

### 3. Create the database

```bash
createdb -U postgres secure_chat
```

### 4. Run the server

```powershell
.\gradlew.bat bootRun
```

On startup the application:

1. Applies Flyway migrations (users table)
2. Starts the HTTPS REST server on port `8443`
3. Starts the TLS chat server on port `5000`

### 5. Run the client

The client is a separate console application. Run it from your IDE
(`org.ugina.client.ChatClient`) — enable **Allow multiple instances** in the run
configuration to launch several clients at once. It reads `CHAT_HOST`,
`CHAT_TLS_PORT`, `AUTH_URL`, and the `TLS_TRUSTSTORE*` variables from the
environment.

> Running the client via Gradle is **not recommended** — Gradle captures stdin
> and breaks interactive input. Use the IDE run configuration instead.

### Typical flow

1. Start the server.
2. Launch two client instances.
3. In each: register a username/password (password ≥ 8 characters), then log in.
4. Message a peer with `@username message text` — the first message triggers an
   automatic E2E handshake, subsequent ones reuse the session key.
5. Run `/safety <username>` on both sides and compare the number over a separate
   channel (in person, by phone, in a signed message) to rule out a server-side
   key substitution.

### Key verification

On first contact the client pins the peer's public-key fingerprint in
`~/.secure-chat/known-peers.tsv`. If the server later returns a different key,
the client refuses to use it and prints a warning with the expected and offered
fingerprints. After verifying the new key out of band, accept it with:

```text
/safety <user>                       # show the safety number to compare
/fingerprint                         # show your own key fingerprint
/trust <user> <fingerprint-prefix>   # accept a changed key (at least 16 hex chars)
```

This is Trust On First Use (TOFU): the first contact still trusts the server,
so compare the safety number when you first connect. Fully removing that risk
requires key transparency — see [`SECURITY.md`](SECURITY.md).

---

## Project Structure

```
app/src/main/java/org/ugina/
├── App.java                  # Spring Boot entry point
├── auth/                     # Authentication (BCrypt, JWT, token validation)
├── config/                   # Spring config, TLS properties, TCP bootstrap
├── controller/               # REST controllers (auth) + error handling
├── dto/                      # Request/response DTOs
├── entity/                   # JPA entities (User)
├── repository/               # Spring Data repositories
├── client/                   # Chat client (console TUI, sessions, TLS)
│   ├── ChatClientCore.java   #   handshake + message routing
│   ├── SessionContext.java   #   per-peer session state machine
│   ├── PeerTrustStore.java   #   TOFU store for peer identity keys
│   └── ConsoleTui.java       #   interactive prompt
├── server/                   # Chat server (TLS, routing, validation)
├── protocol/                 # Message types, commands, error codes
├── crypto/                   # Cryptographic primitives
│   ├── AesCrypto             #   AES-256-GCM
│   ├── SessionCrypto         #   v2 E2E protocol (HKDF, transcript, AAD)
│   ├── KeyFingerprint        #   identity-key fingerprint
│   ├── SafetyNumber          #   safety number for key comparison
│   ├── RsaCrypto             #   RSA-2048 keys + validation
│   ├── RsaSignature          #   SHA256withRSA signatures
│   ├── EcdhCrypto            #   ephemeral ECDH (P-256)
│   ├── HkdfCrypto            #   HKDF (RFC 5869)
│   ├── PbeUtil               #   password-based encryption (PBKDF2)
│   └── keyStorage/           #   file-based identity key storage
└── utils/                    # Frame reader, username policy, logging

app/src/main/resources/
├── application.yml           # hardened runtime configuration
├── logback.xml
└── db/migration/             # Flyway SQL migrations
```

---

## Architecture Overview

The system uses these distinct key types, each with a single responsibility:

| Key | Algorithm | Scope | Purpose |
|-----|-----------|-------|---------|
| Identity key | RSA-2048 | Per user, long-lived | Signs ephemeral keys during handshake |
| Ephemeral key | ECDH P-256 | Per session | Derives the shared secret, then destroyed |
| Session keys | AES-256-GCM | Per session, per direction | Encrypts message content (E2E) |
| TLS certificate | X.509 / TLS 1.3 | Per server | Protects client-server transport |

A message is encrypted once with the E2E session key. TLS then protects that
ciphertext (and the routing metadata) in transit. The server sees metadata but
never message content; a network observer sees neither.

Authentication is abstracted behind an `AuthProvider` interface. The current
implementation is local (BCrypt + JWT), but the abstraction is designed to allow
swapping in an external provider (e.g. Keycloak) without touching the chat layer.

For the complete handshake sequence and message formats, see
[`protocol/EN/PROTOCOL_07.md`](protocol/EN/PROTOCOL_07.md). For the threat model
and residual risks, see [`SECURITY.md`](SECURITY.md).

---

## Roadmap

### v0.1–v0.3 — done
- Basic TCP chat with multiple clients
- Transport encryption
- End-to-end encryption via RSA + AES hybrid scheme
- Replay protection (timestamp + nonce)

### v0.4 — done
- Forward secrecy via ephemeral ECDH keys
- Persistent password-protected RSA identity keys
- Authenticated handshake (ephemeral keys signed with identity key)
- HKDF-based session key derivation

### v0.5 — done
- User registration and login (REST API)
- JWT-based authentication
- PostgreSQL persistence with Flyway migrations
- Session lifecycle (idle + absolute timeout, key rotation)

### v0.6 — done
- TLS 1.3 replaces the static PSK transport layer
- v2 handshake: transcript-bound HKDF, directional keys, explicit confirmation
- Strict per-message sequence numbers (replay/reordering protection)
- Default-deny HTTP authorization and hardened runtime configuration
- Rate limiting and bounded frames / thread pools
- Peer key verification: TOFU pinning, safety numbers, `/trust`
- Local development certificate tooling and `SECURITY.md`

### v0.7 — in progress
- **Per-message forward secrecy (Double Ratchet) — done**: E2E protocol v3,
  HMAC chains + DH ratchet, covered by `RatchetTest`
- **Refresh tokens and token revocation — done**: rotation, reuse detection,
  `token_version`, `/refresh`, `/logout`, covered by `AUTH_FLOW_OK`
- **Identity-key rotation — done**: `/rotate-key` (step-up: session + password),
  self-healing signature verification, covered by `KEY_ROTATE_E2E_OK`
- Key transparency (append-only log) for key verification without manual comparison

### v1.0 — planned
- WebSocket transport + web client
- Multiple device support (per-device keys)
- Persistent message history and offline delivery

---

## Security Notes

This is a learning project. It implements real cryptographic constructions
correctly and is covered by unit tests, but it is **not audited** and should not
be used to protect sensitive communications. Known limitations — including
first-contact trust in the server (TOFU), the lack of key transparency,
per-message forward secrecy, and best-effort memory wiping — are tracked in
[`SECURITY.md`](SECURITY.md).

---

## License

MIT
