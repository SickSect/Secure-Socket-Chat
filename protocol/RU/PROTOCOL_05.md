# Secure Chat — Protocol Specification

> Version 0.5 · Wire protocol for the end-to-end encrypted chat
> Двуязычный документ: **English** ниже, **русская версия** в конце.

---

# English

## 1. Overview

Secure Chat uses two separate channels:

- **REST (HTTP, port 8080)** — authentication: registration and login. Returns a JWT.
- **TCP (port 5000)** — the chat itself. All frames are line-delimited JSON, encrypted with a transport key (PSK).

Two layers of encryption protect chat traffic:

1. **Transport layer (PSK / AES-GCM)** — every TCP frame is encrypted with a pre-shared key. Protects metadata in transit. The server can decrypt this layer.
2. **End-to-end layer (session key / AES-GCM)** — message bodies are encrypted with a per-session key derived between two clients. The server **cannot** decrypt this layer.

## 2. Authentication (REST)

### POST /api/auth/register
Request: `username`, `password`, `publicKey` (Base64 RSA).
Response: `201 Created` on success, `409` if name taken, `400` on validation failure, `429` if rate-limited.

### POST /api/auth/login
Request: `username`, `password`.
Response: `200 OK` with `{ token, expiresAt }`. `401` on bad credentials, `429` if rate-limited.

The returned **JWT** is the client's proof of identity when joining the chat. It carries the username (subject), is signed by the server, and expires after a configured interval.

## 3. Transport framing (TCP)

Every TCP line is:

```
AES-GCM( JSON(message), PSK ) → Base64 → newline
```

The receiver Base64-decodes, decrypts with the PSK, then parses JSON. Two message shapes exist: **ClientMessage** (client → server) and **ServerMessage** (server → client).

## 4. Client → Server messages (ClientMessage)

Discriminated by `commandType`.

| commandType | Purpose | Key fields |
|-------------|---------|------------|
| `JOIN` | Enter the chat after login | `jwt` |
| `SEND_MESSAGE` | Deliver an E2E-encrypted DM | `toClientName`, `e2ePayload`, `nonce`, `timestamp` |
| `GET_KEY` | Request a peer's RSA public key | `toClientName` |
| `INIT_SESSION` | Start an E2E handshake | `toClientName`, `ephemeralPublicKey`, `signature` |
| `SESSION_ACK` | Answer a handshake | `toClientName`, `ephemeralPublicKey`, `signature` |
| `QUIT` | Leave gracefully | — |

Note: `JOIN` carries **only the JWT** — never a raw username. The server derives identity from the signed token, so a client cannot impersonate another.

## 5. Server → Client messages (ServerMessage)

Discriminated by `type`.

| type | Purpose | Key fields |
|------|---------|------------|
| `SYSTEM` | Informational (e.g. welcome) | `text` |
| `DM` | Incoming E2E message | `fromClientName`, `e2ePayload` |
| `DELIVERED` | Delivery confirmation | — |
| `ERROR` | Something failed | `errorCode`, `text` |
| `PUBLIC_KEY` | Reply to GET_KEY | `username`, `publicKey` |
| `INIT_SESSION` | Forwarded handshake start | `fromClientName`, `ephemeralPublicKey`, `signature` |
| `SESSION_ACK` | Forwarded handshake answer | `fromClientName`, `ephemeralPublicKey`, `signature` |

## 6. Error codes

| errorCode | Meaning |
|-----------|---------|
| `INVALID_NAME` | Username rejected |
| `NAME_TAKEN` | Name already connected |
| `INVALID_PUBLIC_KEY` | Public key failed to parse |
| `RECIPIENT_OFFLINE` | Target user not connected |
| `EXPIRED` | Message timestamp too old |
| `REPLAY` | Nonce already seen |
| `DECRYPTION_FAILED` | Could not decrypt |
| `INVALID_FORMAT` | Malformed message |
| `INTERNAL_ERROR` | Server-side fault |
| `INVALID_TOKEN` | JWT invalid or expired |

## 7. Flows

### 7.1 Login + Join

```
Client                          Server
  | --- POST /login ----------->  |
  | <-- 200 { token } ----------  |   (REST, port 8080)
  |                               |
  | === open TCP socket =======>  |   (port 5000)
  | --- JOIN(jwt) ------------->   |
  |                          validate JWT, take username
  |                          register in room, store public key
  | <-- SYSTEM("Welcome") ------  |
```

If the token is bad → `ERROR(INVALID_TOKEN)` and the join fails.

### 7.2 Establishing an E2E session (handshake)

Triggered the first time Alice messages Bob (or after a session expires).

```
Alice                     Server                     Bob
  |                          |                         |
  | -- GET_KEY(Bob) -------> |                         |   (if Bob's RSA key unknown)
  | <- PUBLIC_KEY(Bob) ----- |                         |
  |                          |                         |
  | generate ephemeral ECDH  |                         |
  | sign eph. key with RSA   |                         |
  | -- INIT_SESSION -------> | -- INIT_SESSION ------> |
  |                          |                  verify Alice's signature
  |                          |                  generate ephemeral ECDH
  |                          |                  derive session key (ECDH+HKDF)
  |                          |                  wipe ephemeral private
  | <- SESSION_ACK --------- | <- SESSION_ACK -------- |
  | verify Bob's signature   |                         |
  | derive same session key  |                         |
  | wipe ephemeral private   |                         |
  |                          |                         |
 [both now share a session key; ephemeral keys destroyed]
```

The server only **forwards** handshake frames — it never sees the session key. Signatures over the ephemeral keys authenticate both parties, defeating man-in-the-middle.

### 7.3 Sending a message

```
Alice                          Server                       Bob
  | encrypt text with          |                             |
  | session key (E2E)          |                             |
  | -- SEND_MESSAGE ---------> |                             |
  |                       check timestamp (< 30s)            |
  |                       check nonce (not replayed)         |
  |                       (cannot read body — no key)        |
  |                            | -- DM(e2ePayload) --------> |
  |                            |                    decrypt with session key
  | <- DELIVERED ------------- |                             |
```

The server validates freshness (timestamp) and uniqueness (nonce) on the transport envelope, then relays the still-encrypted body. Only Bob can read it.

## 8. Session lifecycle

- A session key is reused for subsequent messages to the same peer.
- A session **expires** after an idle period or an absolute maximum age; the next message triggers a fresh handshake (key rotation).
- On expiry, disconnect, or graceful exit, the session key is **zeroized** (overwritten with zeros) in client memory.

## 9. Security properties

- **End-to-end confidentiality** — the server cannot read message bodies.
- **Forward secrecy** — ephemeral ECDH keys per session, destroyed after use.
- **Authentication** — ephemeral keys signed by long-term RSA identity; identity in chat derived from a signed JWT, not client claims.
- **Replay protection** — per-message nonce + timestamp window.
- **Key hygiene** — session keys zeroized on every exit path (best-effort within JVM limits).

---

# Русская версия

## 1. Обзор

Secure Chat использует два отдельных канала:

- **REST (HTTP, порт 8080)** — аутентификация: регистрация и логин. Возвращает JWT.
- **TCP (порт 5000)** — сам чат. Все кадры — JSON, разделённый переводами строк, зашифрованный транспортным ключом (PSK).

Трафик чата защищён двумя слоями шифрования:

1. **Транспортный слой (PSK / AES-GCM)** — каждый TCP-кадр шифруется общим ключом. Защищает метаданные при передаче. Сервер может расшифровать этот слой.
2. **End-to-end слой (ключ сессии / AES-GCM)** — тела сообщений шифруются ключом, выведенным между двумя клиентами. Сервер **не может** расшифровать этот слой.

## 2. Аутентификация (REST)

### POST /api/auth/register
Запрос: `username`, `password`, `publicKey` (RSA в Base64).
Ответ: `201 Created` при успехе, `409` если имя занято, `400` при ошибке валидации, `429` при превышении лимита.

### POST /api/auth/login
Запрос: `username`, `password`.
Ответ: `200 OK` с `{ token, expiresAt }`. `401` при неверных данных, `429` при лимите.

Полученный **JWT** — доказательство личности клиента при входе в чат. Содержит имя пользователя (subject), подписан сервером, истекает через заданный интервал.

## 3. Транспортное обрамление (TCP)

Каждая TCP-строка:

```
AES-GCM( JSON(сообщение), PSK ) → Base64 → перевод строки
```

Получатель декодирует Base64, расшифровывает PSK, парсит JSON. Две формы сообщений: **ClientMessage** (клиент → сервер) и **ServerMessage** (сервер → клиент).

## 4. Сообщения Клиент → Сервер (ClientMessage)

Различаются по `commandType`.

| commandType | Назначение | Ключевые поля |
|-------------|------------|---------------|
| `JOIN` | Вход в чат после логина | `jwt` |
| `SEND_MESSAGE` | Доставить E2E-зашифрованное сообщение | `toClientName`, `e2ePayload`, `nonce`, `timestamp` |
| `GET_KEY` | Запросить RSA-ключ собеседника | `toClientName` |
| `INIT_SESSION` | Начать E2E-handshake | `toClientName`, `ephemeralPublicKey`, `signature` |
| `SESSION_ACK` | Ответить на handshake | `toClientName`, `ephemeralPublicKey`, `signature` |
| `QUIT` | Корректный выход | — |

Важно: `JOIN` несёт **только JWT** — никогда не имя в открытом виде. Сервер берёт личность из подписанного токена, поэтому клиент не может выдать себя за другого.

## 5. Сообщения Сервер → Клиент (ServerMessage)

Различаются по `type`.

| type | Назначение | Ключевые поля |
|------|------------|---------------|
| `SYSTEM` | Информационное (напр. приветствие) | `text` |
| `DM` | Входящее E2E-сообщение | `fromClientName`, `e2ePayload` |
| `DELIVERED` | Подтверждение доставки | — |
| `ERROR` | Произошла ошибка | `errorCode`, `text` |
| `PUBLIC_KEY` | Ответ на GET_KEY | `username`, `publicKey` |
| `INIT_SESSION` | Пересланное начало handshake | `fromClientName`, `ephemeralPublicKey`, `signature` |
| `SESSION_ACK` | Пересланный ответ handshake | `fromClientName`, `ephemeralPublicKey`, `signature` |

## 6. Коды ошибок

| errorCode | Значение |
|-----------|----------|
| `INVALID_NAME` | Имя отклонено |
| `NAME_TAKEN` | Имя уже подключено |
| `INVALID_PUBLIC_KEY` | Публичный ключ не распарсился |
| `RECIPIENT_OFFLINE` | Получатель не в сети |
| `EXPIRED` | Метка времени сообщения слишком старая |
| `REPLAY` | Nonce уже встречался |
| `DECRYPTION_FAILED` | Не удалось расшифровать |
| `INVALID_FORMAT` | Некорректное сообщение |
| `INTERNAL_ERROR` | Внутренняя ошибка сервера |
| `INVALID_TOKEN` | JWT недействителен или истёк |

## 7. Сценарии

### 7.1 Логин + вход в чат

```
Клиент                         Сервер
  | --- POST /login ----------->  |
  | <-- 200 { token } ----------  |   (REST, порт 8080)
  |                               |
  | === открыть TCP-сокет ======> |   (порт 5000)
  | --- JOIN(jwt) ------------->   |
  |                          проверить JWT, взять имя
  |                          зарегистрировать, сохранить публичный ключ
  | <-- SYSTEM("Welcome") ------  |
```

Если токен плохой → `ERROR(INVALID_TOKEN)`, вход не удаётся.

### 7.2 Установка E2E-сессии (handshake)

Запускается при первом сообщении Alice → Bob (или после истечения сессии).

```
Alice                     Сервер                     Bob
  |                          |                         |
  | -- GET_KEY(Bob) -------> |                         |   (если RSA-ключ Bob неизвестен)
  | <- PUBLIC_KEY(Bob) ----- |                         |
  |                          |                         |
  | сгенерировать эфем. ECDH |                         |
  | подписать ключ через RSA |                         |
  | -- INIT_SESSION -------> | -- INIT_SESSION ------> |
  |                          |                  проверить подпись Alice
  |                          |                  сгенерировать эфем. ECDH
  |                          |                  вывести ключ сессии (ECDH+HKDF)
  |                          |                  стереть эфем. приватный
  | <- SESSION_ACK --------- | <- SESSION_ACK -------- |
  | проверить подпись Bob    |                         |
  | вывести тот же ключ      |                         |
  | стереть эфем. приватный  |                         |
  |                          |                         |
 [у обоих общий ключ сессии; эфемерные ключи уничтожены]
```

Сервер только **пересылает** кадры handshake — он никогда не видит ключ сессии. Подписи над эфемерными ключами аутентифицируют обе стороны, защищая от «человека посередине».

### 7.3 Отправка сообщения

```
Alice                          Сервер                       Bob
  | зашифровать текст          |                             |
  | ключом сессии (E2E)        |                             |
  | -- SEND_MESSAGE ---------> |                             |
  |                       проверить timestamp (< 30с)        |
  |                       проверить nonce (не повтор)        |
  |                       (тело прочитать не может)          |
  |                            | -- DM(e2ePayload) --------> |
  |                            |                    расшифровать ключом сессии
  | <- DELIVERED ------------- |                             |
```

Сервер проверяет свежесть (timestamp) и уникальность (nonce) транспортной обёртки, затем пересылает всё ещё зашифрованное тело. Прочитать его может только Bob.

## 8. Жизненный цикл сессии

- Ключ сессии переиспользуется для последующих сообщений тому же собеседнику.
- Сессия **истекает** после периода простоя или достижения максимального возраста; следующее сообщение запускает новый handshake (ротация ключа).
- При истечении, обрыве или штатном выходе ключ сессии **зануляется** (перезаписывается нулями) в памяти клиента.

## 9. Свойства безопасности

- **End-to-end конфиденциальность** — сервер не может читать тела сообщений.
- **Forward secrecy** — эфемерные ECDH-ключи на сессию, уничтожаются после использования.
- **Аутентификация** — эфемерные ключи подписаны постоянным RSA; личность в чате берётся из подписанного JWT, а не из слов клиента.
- **Защита от replay** — nonce на сообщение + окно по timestamp.
- **Гигиена ключей** — ключи сессии зануляются на каждом пути выхода (best-effort в пределах ограничений JVM).

---

*This specification reflects the v0.5 wire protocol. Implementation details (class names, internal methods) are documented separately in the codebase.*