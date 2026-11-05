# Secure Chat — спецификация протокола v2 (v0.6)

Статус: актуально для релиза **v0.6**.
Предыдущие версии: [`PROTOCOL_05.md`](PROTOCOL_05.md).

---

## 1. Обзор

Secure Chat состоит из двух независимых каналов:

1. **REST API по HTTPS** — регистрация и вход, выдача JWT.
2. **TCP-чат по TLS 1.3** — JOIN, handshake, обмен сообщениями.

Содержимое сообщений дополнительно шифруется сквозным образом (E2E) на
клиентах. Сервер видит только метаданные и непрозрачный `e2ePayload`.

Что изменилось в v2 по сравнению с v1:

| v1 | v2 |
|----|----|
| Один общий ключ AES на сессию | Отдельные ключи для каждого направления |
| HKDF с постоянным `info` | HKDF с солью = SHA-256 транскрипта handshake |
| Нет подтверждения ключей | Явные `SESSION_CONFIRM` / теги подтверждения |
| Нет защиты от replay на уровне E2E | Монотонный sequence number в AAD |
| Подпись только эфемерного ключа | Подпись привязана к роли и обоим именам |
| Статический PSK на транспорте | TLS 1.3 |

---

## 2. Транспорт и кадрирование

- REST: HTTPS, только TLS 1.3, порт по умолчанию `8443`.
- Чат: TLS 1.3, порт по умолчанию `5000`.
- Кадр — одна строка UTF-8, завершённая `\n`. `\r` игнорируется.
- Максимальная длина кадра — **96 KiB** (96 × 1024 символов) на клиенте и на
  сервере. Превышение закрывает соединение.
- JSON кодируется Jackson. Неизвестные поля игнорируются.
- Клиент проверяет имя хоста TLS
  (`endpointIdentificationAlgorithm=HTTPS`) и использует отдельный truststore
  (`TLS_TRUSTSTORE`).

---

## 3. Аутентификация (REST)

### POST /api/auth/register

```json
{
  "username": "alice",
  "password": "correct horse battery staple",
  "publicKey": "<Base64 X.509 RSA public key>"
}
```

Ограничения:

- `username`: 3–32 символа, только `[A-Za-z0-9_]`.
- `password`: 8–128 символов.
- `publicKey`: валидный RSA-ключ не меньше 2048 бит, public exponent ≥ 65537.

Ответ `201 Created`:

```json
{ "status": "registered", "username": "alice" }
```

Ошибки:

- `400` — ошибка валидации (`VALIDATION_FAILED`).
- `409` — имя занято или ключ отклонён (`REGISTRATION_FAILED`).
- `429` — превышен лимит регистраций (`RATE_LIMIT_EXCEEDED`).

### POST /api/auth/login

```json
{ "username": "alice", "password": "correct horse battery staple" }
```

Ответ `200 OK`:

```json
{ "token": "<JWT>", "expiresAt": 1760000000000 }
```

Ошибки:

- `401` — неверные учётные данные (`AUTHENTICATION_FAILED`).
- `429` — превышен лимит попыток (`RATE_LIMIT_EXCEEDED`).

JWT:

- алгоритм HS256;
- issuer `secure-chat`;
- `sub` = username;
- срок жизни — `JWT_EXPIRATION_MINUTES` (по умолчанию 60 минут).

---

## 4. Сообщения клиент → сервер (`ClientMessage`)

Все поля опциональны; используется только то, что нужно команде.

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

| `commandType` | Обязательные поля | Назначение |
|---------------|-------------------|------------|
| `JOIN` | `jwt` | Вход в чат; имя и ключ берутся из БД по токену |
| `GET_KEY` | `toClientName` | Получить RSA-ключ собеседника |
| `INIT_SESSION` | `toClientName`, `ephemeralPublicKey`, `signature` | Начать handshake |
| `SESSION_ACK` | `toClientName`, `ephemeralPublicKey`, `signature`, `confirmation` | Ответ на handshake |
| `SESSION_CONFIRM` | `toClientName`, `confirmation` | Подтвердить ключи |
| `SEND_MESSAGE` | `toClientName`, `e2ePayload`, `timestamp`, `nonce` | Отправить E2E-сообщение |
| `QUIT` | — | Отключиться |

Ограничения полей:

- `toClientName` — по политике имён (1–32, `[A-Za-z0-9_]`);
- `nonce` — Base64 ровно от 16 байт, не длиннее 64 символов;
- `e2ePayload` — непустой Base64, не длиннее 96 KiB;
- `ephemeralPublicKey` — не длиннее 2 KiB;
- `signature` — не длиннее 2 KiB;
- `confirmation` — не длиннее 512 символов;
- `timestamp` — миллисекунды Unix, отклоняется при расхождении > 30 секунд.

---

## 5. Сообщения сервер → клиент (`ServerMessage`)

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

| `type` | Поля | Назначение |
|--------|------|------------|
| `SYSTEM` | `text` | Системное сообщение / успешный JOIN |
| `DM` | `fromClientName`, `e2ePayload` | Доставка E2E-сообщения |
| `DELIVERED` | — | Сообщение принято сервером |
| `ERROR` | `errorCode`, `text` | Ошибка |
| `PUBLIC_KEY` | `username`, `publicKey` | Ответ на `GET_KEY` |
| `INIT_SESSION` | `fromClientName`, `ephemeralPublicKey`, `signature` | Пересылка INIT |
| `SESSION_ACK` | `fromClientName`, `ephemeralPublicKey`, `signature`, `confirmation` | Пересылка ACK |
| `SESSION_CONFIRM` | `fromClientName`, `confirmation` | Пересылка CONFIRM |

---

## 6. Handshake v2

Обозначения:

- `A` — инициатор, `B` — ответчик.
- `ID_A`, `ID_B` — имена пользователей.
- `(E_A, e_A)`, `(E_B, e_B)` — эфемерные пары P-256.
- `K` — общий секрет ECDH.
- `H` — SHA-256 транскрипта.

### 6.1. Каноническая подпись

Перед подписью строится длина-префиксная строка:

```
LABEL = "secure-chat/v2/handshake"
payload = len(LABEL)||LABEL || len(role)||role || len(signer)||signer ||
          len(peer)||peer || len(ephemeralPub)||ephemeralPub
```

`len(x)` — 4 байта big-endian. Все строки — UTF-8.

- Инициатор подписывает `role = "init"`, `signer = ID_A`, `peer = ID_B`,
  `ephemeralPub = E_A`.
- Ответчик подписывает `role = "ack"`, `signer = ID_B`, `peer = ID_A`,
  `ephemeralPub = E_B`.

Подпись — `SHA256withRSA` ключом identity. Привязка роли и обоих имён не даёт
переиграть захваченный INIT другому собеседнику или в обратном направлении.

### 6.2. Транскрипт и вывод ключей

```
transcript = len("secure-chat/v2/transcript") ||
             len(ID_A) || len(ID_B) || len(E_A) || len(E_B)

H = SHA-256(transcript)
```

HKDF-SHA256 (`HkdfCrypto.derive`):

```
i2r               = HKDF(K, salt = H, info = "secure-chat/v2/i2r",               32)
r2i               = HKDF(K, salt = H, info = "secure-chat/v2/r2i",               32)
initiator-confirm = HKDF(K, salt = H, info = "secure-chat/v2/initiator-confirm", 32)
responder-confirm = HKDF(K, salt = H, info = "secure-chat/v2/responder-confirm", 32)
```

Направления:

- `A` шифрует `i2r`, расшифровывает `r2i`;
- `B` шифрует `r2i`, расшифровывает `i2r`.

### 6.3. Последовательность

```
A                                   сервер                                   B
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

Шаги:

1. `A` получает `rsaB`, генерирует `(E_A, e_A)`, подписывает payload и шлёт
   `INIT_SESSION`.
2. `B` проверяет подпись `A` по `rsaA` (полученному через `GET_KEY`).
3. `B` генерирует `(E_B, e_B)`, считает `K`, `H` и ключи, подписывает
   `role="ack"`, вычисляет `conf_B`, отправляет `SESSION_ACK`.
4. `A` проверяет подпись `B`, считает `K`, `H`, ключи, сравнивает `conf_B`
   в постоянном времени. При успехе отправляет `SESSION_CONFIRM` с `conf_A`,
   затем помечает сессию `READY`.
5. `B` сравнивает `conf_A` в постоянном времени и только после этого помечает
   сессию `READY`.

Сессия не используется для сообщений до завершения подтверждения.

### 6.4. Одновременный handshake

Если `A` и `B` начинают handshake одновременно, применяется детерминированное
правило: сторону с лексикографически меньшим именем оставляем инициатором.
Вторая сторона уничтожает свой pending-контекст и отвечает как responder.
Это не даёт двум контекстам перезаписать друг друга.

---

## 7. Формат E2E-сообщения

`e2ePayload` — Base64 от:

```
+--------+------------------+------------+----------------------------+
| ver(1) | sequence(8, BE)  | IV(12)     | AES-256-GCM ciphertext+tag |
+--------+------------------+------------+----------------------------+
```

AAD:

```
ver || len(sender)||sender || len(recipient)||recipient || sequence(8, BE)
```

Правила приёма:

1. Длина ≥ 1 + 8 + 12 + 16 байт.
2. `ver == 2`.
3. `sequence == lastReceived + 1` (строго, без пропусков).
4. GCM-тег должен совпасть.

Только после успешной расшифровки счётчик получателя увеличивается. Это
отклоняет replay, переупорядочивание и вставку чужих кадров. Счётчик отправки
начинается с 0 и увеличивается на 1 для каждого сообщения.

Nonce и timestamp в `SEND_MESSAGE` — дополнительная грубая защита на уровне
сервера (кэш `(sender, nonce)` на 60 секунд, допуск часов ±30 секунд). Основная
защита целостности — sequence number в E2E-конверте.

---

## 8. Жизненный цикл сессии

- `WAITING_FOR_ACK` — инициатор отправил INIT.
- `WAITING_FOR_CONFIRM` — ответчик отправил ACK и ждёт CONFIRM.
- `READY` — ключи подтверждены, можно слать сообщения.
- `FAILED` — handshake отклонён или уничтожен.

Таймауты:

- idle — 30 минут без активности;
- absolute — 24 часа с момента создания.

При истечении сессия уничтожается вместе с ключами, а следующее сообщение
запускает новый handshake. При отключении клиента все сессии уничтожаются.

Сервер:

- idle-таймаут соединения — 30 минут;
- лимит команд — 60 за 10 секунд на соединение;
- пул потоков — 8–64 потока, очередь 256; при переполнении соединение
  отклоняется;
- одновременно разрешено одно соединение на username.

---

## 9. Коды ошибок

| Код | Значение |
|-----|----------|
| `INVALID_NAME` | Некорректное имя пользователя |
| `NAME_TAKEN` | Имя уже подключено |
| `INVALID_PUBLIC_KEY` | Некорректный или слабый публичный ключ |
| `RECIPIENT_OFFLINE` | Получатель не подключён / не найден |
| `EXPIRED` | Устаревший timestamp |
| `REPLAY` | Повторный nonce |
| `DECRYPTION_FAILED` | Ошибка расшифровки |
| `INVALID_FORMAT` | Некорректный JSON/поля/размер |
| `RATE_LIMITED` | Превышен лимит команд |
| `INTERNAL_ERROR` | Внутренняя ошибка |
| `INVALID_TOKEN` | JWT отсутствует, истёк или неверен |

---

## 10. Свойства безопасности

Обеспечивается:

- конфиденциальность содержимого от сервера и сети (E2E + TLS);
- целостность и аутентичность сообщений (GCM + AAD);
- защита от replay/переупорядочивания в рамках сессии;
- forward secrecy на сессию (эфемерные ECDH-ключи уничтожаются);
- аутентификация handshake долгоживущими RSA-ключами;
- привязка ключей к транскрипту и направлениям;
- защита от подмены имени в чате (имя берётся из JWT).

Не обеспечивается (см. [`SECURITY.md`](../../SECURITY.md)):

- защита от активного malicious-сервера, который подменяет публичные ключи;
- per-message forward secrecy;
- safety numbers / проверка отпечатков;
- отзыв JWT и refresh-токены;
- сокрытие метаданных от сервера.

---

## 11. Константы

| Параметр | Значение |
|----------|----------|
| Версия E2E | `2` |
| Кривая ECDH | `secp256r1` (P-256) |
| Identity | RSA ≥ 2048, `SHA256withRSA` |
| Симметричный шифр | AES-256-GCM, тег 128 бит |
| IV | 12 байт, случайный на сообщение |
| HKDF | HMAC-SHA256 |
| Транскрипт | SHA-256 |
| PBKDF2 | HMAC-SHA256, 600 000 итераций, соль 16 байт |
| Формат файла ключа | `SCK1` + salt + IV + ciphertext |
| Таймаут handshake на клиенте | 10 секунд |
| Idle-таймаут сессии | 30 минут |
| Absolute-таймаут сессии | 24 часа |
| Допуск timestamp | ±30 секунд |
| Максимальный кадр | 96 KiB |
