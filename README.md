# Secure Chat

A TCP-based end-to-end encrypted chat built from scratch in Java, focused on
understanding cryptographic primitives directly rather than relying on high-level
libraries.

The current release (**v0.6**) keeps the end-to-end encryption core and hardens
the deployment around it: TLS 1.3 everywhere, a transcript-bound v2 handshake
with explicit key confirmation, strict message sequence numbers, JWT-authenticated
chat access, PostgreSQL-backed users, and fail-closed configuration.

> **Security documentation** — threat model, key hierarchy, and residual risks
> are documented in [`SECURITY.md`](SECURITY.md). The full protocol
> specification is in [`protocol/EN/PROTOCOL_06.md`](protocol/EN/PROTOCOL_06.md)
> (Russian: [`protocol/RU/PROTOCOL_06.md`](protocol/RU/PROTOCOL_06.md)).

---

## Features

- **End-to-end encryption** — message content is encrypted with directional
  AES-256-GCM session keys. The server only routes ciphertext and cannot read
  messages.
- **Forward secrecy per session** — session keys are derived from ephemeral ECDH
  (P-256) key pairs that are destroyed after the handshake.
- **Transcript-bound key derivation** — HKDF-SHA256 uses the full handshake
  transcript (both identities and both ephemeral keys) as salt, so keys cannot
  be reused across peers or sessions.
- **Explicit key confirmation** — both sides prove they derived the same keys
  before the session becomes usable.
- **Replay and reordering protection** — every E2E payload carries a monotonic
  sequence number authenticated as GCM AAD.
- **Authenticated handshake** — ephemeral keys are signed with the long-lived
  RSA-2048 identity key; the signature binds the role and both usernames.
- **Persistent identity** — each user has a long-lived RSA key pair stored
  locally in a password-protected file (PBKDF2 600k + AES-GCM).
- **TLS 1.3 transport** — both REST (HTTPS) and the chat TCP port use TLS 1.3;
  the old static pre-shared key has been removed.
- **JWT authentication** — registration and login over REST; the chat identity
  is taken from the validated token, not from client claims.
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
│   └── ConsoleTui.java       #   interactive prompt
├── server/                   # Chat server (TLS, routing, validation)
├── protocol/                 # Message types, commands, error codes
├── crypto/                   # Cryptographic primitives
│   ├── AesCrypto             #   AES-256-GCM
│   ├── SessionCrypto         #   v2 E2E protocol (HKDF, transcript, AAD)
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
[`protocol/EN/PROTOCOL_06.md`](protocol/EN/PROTOCOL_06.md). For the threat model
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

### v0.6 — current
- TLS 1.3 replaces the static PSK transport layer
- v2 handshake: transcript-bound HKDF, directional keys, explicit confirmation
- Strict per-message sequence numbers (replay/reordering protection)
- Default-deny HTTP authorization and hardened runtime configuration
- Rate limiting and bounded frames / thread pools
- Local development certificate tooling and `SECURITY.md`

### v0.7 — planned
- Safety numbers / key verification (mitigates server-side key substitution)
- Refresh tokens and server-side token revocation
- Per-message forward secrecy (Double Ratchet)

### v1.0 — planned
- WebSocket transport + web client
- Multiple device support (per-device keys)
- Persistent message history and offline delivery

---

## Security Notes

This is a learning project. It implements real cryptographic constructions
correctly and is covered by unit tests, but it is **not audited** and should not
be used to protect sensitive communications. Known limitations — including the
server-trusted key distribution, the lack of per-message forward secrecy, and
best-effort memory wiping — are tracked in [`SECURITY.md`](SECURITY.md).

---

## License

MIT
