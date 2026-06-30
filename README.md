# Secure Chat

A TCP-based end-to-end encrypted chat built from scratch in Java, focused on
understanding cryptographic primitives directly rather than relying on high-level
libraries.

The current release (**v0.5**) adds account authentication, persistence, and session
lifecycle management on top of the end-to-end encryption core: JWT-based login,
PostgreSQL-backed users, session expiry with key rotation, and in-memory key
zeroization.

> **Full protocol details** — message formats, handshake sequences, error codes, and
> security properties — are documented in [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
> (bilingual: English + Russian).

---

## Features

- **End-to-end encryption** — message content is encrypted with a per-session
  AES-256-GCM key. The server only routes ciphertext and cannot read messages.
- **Forward secrecy** — session keys are derived from ephemeral ECDH (P-256) key pairs
  that are destroyed after the handshake. Compromising a long-lived key does not expose
  past sessions.
- **Persistent identity** — each user has a long-lived RSA-2048 key pair, stored locally
  in a password-protected file (PBKDF2 + AES-GCM).
- **Authenticated handshake** — ephemeral keys are signed with the long-lived RSA key;
  the peer verifies the signature, preventing man-in-the-middle key substitution.
- **JWT authentication** — registration and login over REST; chat access is gated by a
  signed token. Identity in chat is taken from the token, not from client claims.
- **Session lifecycle** — sessions expire on idle timeout or absolute age, triggering a
  fresh handshake (key rotation) on the next message.
- **Key zeroization** — session keys are overwritten with zeros in memory on expiry,
  disconnect, or exit (best-effort, working around a known JDK limitation).
- **Replay protection** — messages carry a timestamp and a nonce; the server rejects
  expired or duplicate messages.
- **Transport layer** — all client-server traffic is encrypted with a pre-shared key
  (AES-256-GCM), protecting metadata from passive network observers.

---

## Tech Stack

- **Java 23**
- **Spring Boot** — REST endpoints, dependency injection, configuration
- **Spring Security** — BCrypt password hashing
- **PostgreSQL** + **Flyway** — user persistence and schema migrations
- **JJWT** — JSON Web Token issuance and validation
- **Gradle** — build tooling
- **TestNG** — testing
- Raw TCP sockets for the chat transport (no WebSocket/STOMP — intentional, to work
  with the protocol directly)

---

## Quick Start

### Prerequisites

- JDK 23
- PostgreSQL 16+ (database named `secure_chat`)

### Database setup

Create the database:

```bash
createdb -U postgres secure_chat
```

Provide credentials via environment variables (defaults shown):

```bash
export DB_PASSWORD=postgres
export JWT_SECRET=your-256-bit-secret
```

> Spring Boot does not read `.env` files. Set these as real environment variables, or
> configure them in your IDE run configuration. `JWT_SECRET` must be at least 256 bits.

### Run the server

```bash
./gradlew bootRun
```

On startup the application:
1. Applies Flyway migrations (creates the `users` table)
2. Starts the embedded web server on port `8080` (REST: register / login)
3. Starts the TCP chat server on port `5000`

### Run the client

The client is a separate console application. Run it from your IDE
(`org.ugina.client.ChatClient`) — enable **Allow multiple instances** in the run
configuration to launch several clients at once.

> Running the client via Gradle is **not recommended** — Gradle captures stdin and
> breaks interactive input. Use the IDE run configuration instead.

### Typical flow

1. Start the server.
2. Launch two client instances.
3. In each: register a username/password (password ≥ 8 characters), then log in.
4. Message a peer with `@username message text` — the first message triggers an
   automatic E2E handshake, subsequent ones reuse the session key.

---

## Project Structure

```
src/main/java/org/ugina/
├── App.java                  # Spring Boot entry point
├── auth/                     # Authentication abstraction
│   ├── AuthProvider.java     #   pluggable interface (ready for Keycloak etc.)
│   ├── LocalAuthProvider.java#   local BCrypt + JWT implementation
│   ├── JwtService.java       #   JWT issue / validate
│   └── exceptions/           #   auth-specific exceptions
├── config/                   # Spring config, properties, TCP bootstrap
├── controller/               # REST controllers (auth) + error handling
├── Dto/                      # Request/response DTOs
├── entity/                   # JPA entities (User)
├── repository/               # Spring Data repositories
├── client/                   # Chat client (console TUI, session handling)
├── server/                   # Chat server (TCP, message routing)
├── protocol/                 # Message types, commands, error codes
├── crypto/                   # Cryptographic primitives
│   ├── AesCrypto             #   AES-256-GCM
│   ├── RsaCrypto             #   RSA-2048 key generation
│   ├── RsaSignature          #   SHA256withRSA signatures
│   ├── EcdhCrypto            #   ephemeral ECDH (P-256)
│   ├── HkdfCrypto            #   HKDF (RFC 5869)
│   ├── PbeUtil               #   password-based encryption (PBKDF2)
│   └── keyStorage/           #   file-based identity key storage
└── utils/                    # Logging helper

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

Authentication is abstracted behind an `AuthProvider` interface. The current
implementation is local (BCrypt + JWT), but the abstraction is designed to allow
swapping in an external provider (e.g. Keycloak) without touching the chat layer.

For the complete handshake sequence and message formats, see
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

---

## Roadmap

### v0.1–v0.3 — done
- Basic TCP chat with multiple clients
- AES-256-GCM transport encryption
- End-to-end encryption via RSA + AES hybrid scheme
- Replay protection (timestamp + nonce)

### v0.4 — done
- Forward secrecy via ephemeral ECDH keys
- Persistent password-protected RSA identity keys
- Authenticated handshake (ephemeral keys signed with identity key)
- HKDF-based session key derivation
- Architectural refactor into clear layers

### v0.5 — current
- User registration and login (REST API)
- JWT-based authentication (pluggable `AuthProvider`, ready for Keycloak)
- PostgreSQL persistence with Flyway migrations
- Session lifecycle (idle + absolute timeout, key rotation)
- Memory zeroization for session keys
- Graceful connection-loss handling

### v0.6 — planned
- Rate limiting on auth endpoints
- TLS for the REST and transport layers (replacing the static PSK)
- Refresh tokens
- Self-review hardening (threat model pass)

### v0.7 — planned
- WebSocket transport + web client
- Multiple device support (per-device keys)
- Push-style offline delivery

### v1.0 — planned
- Persistent message history
- Presence (online/offline status)

---

## Security Notes

This is a learning project. It implements real cryptographic constructions correctly,
but is **not** audited and should not be used to protect sensitive communications.
Known limitations are tracked openly — for example, full memory wiping of keys is
constrained by the JVM, and the transport PSK is static pending a move to TLS. A
documented threat model is planned.

---

## License

MIT