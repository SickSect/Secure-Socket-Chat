# Secure Chat

A TCP-based end-to-end encrypted chat built from scratch in Java, with a focus on
understanding cryptographic primitives rather than relying on high-level libraries.

The current release (**v0.4**) implements forward secrecy via ephemeral ECDH keys,
persistent password-protected identity keys, and authenticated handshakes. Work on
**v0.5** (authentication, persistence, session lifecycle) is in progress.

> **Note:** This README is an overview. For the full protocol details, message formats,
> threat model, and cryptographic constants, see the specification documents in
> [`docs/`](docs/) — [`PROTOCOL_EN.md`](docs/PROTOCOL_EN.md) (English) and
> [`PROTOCOL_RU.md`](docs/PROTOCOL_RU.md) (Russian).

---

## Features

- **End-to-end encryption** — message content is encrypted with a per-session AES-256-GCM
  key. The server only routes ciphertext and cannot read messages.
- **Forward secrecy** — session keys are derived from ephemeral ECDH (P-256) key pairs
  that are destroyed after the handshake. Compromising a long-lived key does not expose
  past sessions.
- **Persistent identity** — each user has a long-lived RSA-2048 key pair, stored locally
  in a password-protected file (PBKDF2 + AES-GCM).
- **Authenticated handshake** — ephemeral keys are signed with the long-lived RSA key;
  the peer verifies the signature, preventing man-in-the-middle key substitution.
- **Replay protection** — messages carry a timestamp and a nonce; the server rejects
  expired or duplicate messages.
- **Transport layer** — all client-server traffic is encrypted with a pre-shared key
  (AES-256-GCM), protecting metadata from passive network observers.

---

## Tech Stack

- **Java 23**
- **Spring Boot** (v0.5+) — REST endpoints, dependency injection, configuration
- **PostgreSQL** + **Flyway** — user persistence and schema migrations
- **Gradle** — build tooling
- **TestNG** — testing
- Raw TCP sockets for the chat transport (no WebSocket/STOMP — intentional, to work
  with the protocol directly)

---

## Quick Start

### Prerequisites

- JDK 23
- Docker (recommended) **or** a local PostgreSQL 16+ instance

### Option A — with Docker (recommended)

Spin up PostgreSQL with the database pre-created:

```bash
docker compose up -d
```

This starts PostgreSQL on port `5432` with database `secure_chat` already created.

### Option B — local PostgreSQL

If you already run PostgreSQL locally, create the database manually:

```bash
createdb -U postgres secure_chat
```

Set your database credentials via environment variables (defaults shown):

```bash
export DB_USERNAME=postgres
export DB_PASSWORD=postgres
```

### Run the server

```bash
./gradlew bootRun
```

On startup the application:
1. Applies Flyway migrations (creates the `users` table)
2. Starts the embedded web server on port `8080` (REST endpoints)
3. Starts the TCP chat server on port `5000`

### Run the client

The client is a separate console application. Run it from your IDE
(`org.ugina.client.ChatClient`) — enable **Allow multiple instances** in the run
configuration to launch several clients at once.

> Running clients via `./gradlew runClient` is **not recommended** — Gradle captures
> stdin and breaks interactive input. Use the IDE run configuration instead.

---

## Project Structure

```
src/main/java/org/ugina/
├── Application.java          # Spring Boot entry point
├── auth/                     # Authentication abstraction (AuthProvider)
│   ├── local/                # Local BCrypt + JWT implementation
│   └── exception/            # Auth-specific exceptions
├── config/                   # Spring configuration, TCP server bootstrap
├── controller/               # REST controllers
├── dto/                      # Request/response DTOs
├── entity/                   # JPA entities
├── repository/               # Spring Data repositories
├── client/                   # Chat client (console TUI)
├── server/                   # Chat server (TCP, message routing)
├── protocol/                 # Message types, commands, error codes
└── crypto/                   # Cryptographic primitives
    ├── AesCrypto             # AES-256-GCM
    ├── RsaCrypto             # RSA-2048 key generation
    ├── RsaSignature          # SHA256withRSA signatures
    ├── EcdhCrypto            # Ephemeral ECDH (P-256)
    ├── HkdfCrypto            # HKDF (RFC 5869)
    ├── PbeUtil               # Password-based encryption (PBKDF2)
    └── keyStorage/           # File-based identity key storage

src/main/resources/
└── db/migration/             # Flyway SQL migrations
```

---

## Architecture Overview

The system uses four distinct key types, each with a single responsibility:

| Key | Algorithm | Scope | Purpose |
|-----|-----------|-------|---------|
| Pre-shared key (PSK) | AES-256-GCM | Global | Encrypts all client-server traffic |
| Identity key | RSA-2048 | Per user, long-lived | Signs ephemeral keys during handshake |
| Ephemeral key | ECDH P-256 | Per session | Derives the shared secret, then destroyed |
| Session key | AES-256-GCM | Per session | Encrypts message content (E2E) |

Each message is encrypted twice: once with the session key (end-to-end) and once with
the PSK (transport). The server sees metadata but never message content; the network
provider sees neither.

For the complete handshake sequence and message formats, see
[`docs/PROTOCOL_EN.md`](docs/PROTOCOL_EN.md).

---

## Roadmap

### v0.1–v0.3 — done
- Basic TCP chat with multiple clients
- AES-256-GCM transport encryption
- End-to-end encryption via RSA + AES hybrid scheme
- Replay protection (timestamp + nonce)

### v0.4 — done (current)
- Forward secrecy via ephemeral ECDH keys
- Persistent password-protected RSA identity keys
- Authenticated handshake (ephemeral keys signed with identity key)
- HKDF-based session key derivation
- Architectural refactor into clear layers

### v0.5 — in progress
- User registration and login (REST API)
- JWT-based authentication (pluggable `AuthProvider`, ready for Keycloak)
- PostgreSQL persistence with Flyway migrations
- Session lifecycle (idle + absolute timeout)
- Rate limiting
- Memory zeroization for session keys

### v0.6 — planned
- Per-message forward secrecy (Double Ratchet)
- Verification codes / safety numbers

### v0.7 — planned
- WebSocket transport
- Web client
- Multiple device support

### v1.0 — planned
- Persistent message history
- Offline message delivery
- Presence (online/offline status)

---

## Documentation

- [`protocol/EN/PROTOCOL_04.md`](protocol/EN/PROTOCOL_04.md) — full protocol specification (English)
- [`protocol/EN/PROTOCOL_04.md`](protocol/RU/PROTOCOL_04.md) — full protocol specification (Russian)

The specification covers the connection lifecycle, all message formats, error codes,
the threat model (what is and isn't protected), and every cryptographic constant.

---

## License

MIT