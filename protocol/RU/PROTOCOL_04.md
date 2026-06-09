# Secure Chat Protocol Specification

**Version:** 0.4 (Draft)
**Status:** In development
**Date:** 2026-05-20

---

## 1. Overview

Secure Chat Protocol (SCP) — прикладной протокол поверх TCP для обмена
сообщениями между несколькими клиентами через центральный сервер.

Версия 0.4 добавляет **forward secrecy** через эфемерные ECDH-ключи
и **persistent identity** через защищённое паролем хранение долгоживущих
RSA-ключей. Содержимое сообщений больше не зашифровано долгоживущим
ключом — компрометация identity-ключа не раскрывает прошлые сессии.

### Возможности v0.4

- **Persistent identity** — RSA-ключи клиента сохраняются между запусками
  в файле, защищённом паролем (PBKDF2 + AES-GCM)
- **Forward secrecy** через session-level эфемерные ECDH-ключи
- **Аутентификация handshake** — эфемерные ECDH-ключи подписываются
  долгоживущим RSA-ключом; собеседник проверяет подпись
- **Session keys** — содержимое сообщений шифруется AES-GCM с ключом,
  выведенным через HKDF из ECDH-secret
- RSA в v0.4 используется **только для подписей**, не для шифрования

### Изменение роли RSA

В v0.3 RSA шифровал AES-ключи сообщений (Hybrid scheme). В v0.4 эта
схема заменена: RSA используется только для подписи эфемерных ECDH-ключей
при handshake. Сами сообщения шифруются session_key, который выводится
через ECDH+HKDF и не зависит от RSA-ключей.

---

## 2. Architecture

Протокол имеет три уровня защиты:

### Уровень 1: Транспортный канал (PSK)

Все сообщения между клиентом и сервером шифруются общим pre-shared key
(AES-256-GCM). Защищает метаданные (команды, имена) от пассивного
перехвата провайдером сети.

### Уровень 2: Identity-ключи (RSA-2048)

Долгоживущие RSA-ключи клиентов. Используются для:
- Подписи эфемерных ECDH-ключей при handshake
- Подтверждения личности клиента

Хранятся между запусками клиента в защищённом паролем файле.

### Уровень 3: Session keys (AES-256)

Симметричные ключи сессии, выведенные через ECDH+HKDF между двумя
конкретными клиентами. Шифруют содержимое сообщений. Существуют только
в памяти, уничтожаются после завершения сессии.

---

## 3. Cryptographic Primitives

| Назначение | Алгоритм | Параметры |
|-----------|----------|-----------|
| Transport encryption | AES-GCM | 256-bit key, 96-bit IV, 128-bit tag |
| Identity keys | RSA | 2048-bit, X.509 / PKCS#8 |
| Identity signatures | RSA-PKCS#1 v1.5 | SHA256withRSA |
| Ephemeral keys | ECDH | curve secp256r1 (P-256) |
| Key derivation (from password) | PBKDF2 | HMAC-SHA256, 100 000 iterations |
| Key derivation (from ECDH secret) | HKDF | HMAC-SHA256, RFC 5869 |
| Message encryption | AES-GCM | session_key (256-bit), 96-bit IV |

---

## 4. Connection Lifecycle

### 4.1 Identity setup (один раз для каждого username)

1. Пользователь запускает клиент, вводит username и password
2. Клиент проверяет файл `~/.secure-chat/<username>.key`
3. Если файл существует — расшифровывает приватный ключ паролем
4. Если файла нет — генерирует новую RSA-пару и сохраняет
5. Формат файла:
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

1. Клиент открывает TCP-соединение к серверу (порт 5000 по умолчанию)
2. Клиент отправляет `JOIN` с username и публичным RSA-ключом
3. Сервер регистрирует клиента в реестре
4. Сервер отвечает `SYSTEM` (welcome) или `ERROR` (`NAME_TAKEN`)
5. Клиент готов к обмену сообщениями

### 4.3 Session handshake (новое в v0.4)

При первой отправке сообщения собеседнику инициируется handshake:

**1. Инициатор (Alice → Bob):**
- Получает RSA-public Боба (через `GET_KEY` если не в кеше)
- Генерирует эфемерную ECDH-пару `(eph_a_priv, eph_a_pub)`
- Подписывает `eph_a_pub` своим долгоживущим RSA-приватным
- Отправляет `INIT_SESSION` с `eph_a_pub` и подписью
- Ждёт `SESSION_ACK` (таймаут 10 секунд)

**2. Получатель (Bob):**
- Получает `INIT_SESSION` от сервера
- Получает RSA-public Алисы (если не в кеше)
- Проверяет подпись Алисы; при невалидной — игнорирует
- Генерирует свою эфемерную ECDH-пару `(eph_b_priv, eph_b_pub)`
- Вычисляет `shared_secret = ECDH(eph_b_priv, eph_a_pub)`
- Выводит `session_key = HKDF(shared_secret, "secure-chat-session", 32)`
- Уничтожает `eph_b_priv` (forward secrecy)
- Подписывает `eph_b_pub` своим долгоживущим RSA-приватным
- Отправляет `SESSION_ACK` с `eph_b_pub` и подписью

**3. Завершение у инициатора:**
- Alice получает `SESSION_ACK`
- Проверяет подпись Боба
- Вычисляет `shared_secret = ECDH(eph_a_priv, eph_b_pub)`
- Выводит тот же `session_key`
- Уничтожает `eph_a_priv`

После handshake обе стороны имеют одинаковый `session_key`. Эфемерные
приватные ключи уничтожены. Сессия в состоянии READY.

### 4.4 Message exchange

После установки сессии:
1. Отправитель шифрует текст AES-GCM с `session_key`
2. Формирует `SEND_MESSAGE` с e2ePayload, timestamp, nonce
3. Сервер проверяет timestamp (≤ 30 сек) и nonce (replay protection)
4. Сервер пересылает DM получателю
5. Получатель расшифровывает session_key из своей `SessionContext`

### 4.5 Termination

1. Клиент отправляет `QUIT` или закрывает соединение
2. Сервер удаляет клиента из реестра
3. Эфемерные данные сессий в памяти процесса теряются при завершении JVM

---

## 5. Message Formats

Все сообщения сериализуются в JSON через Jackson и шифруются PSK-ключом.

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

#### INIT_SESSION (новое в v0.4)
```json
{
  "commandType": "INIT_SESSION",
  "toClientName": "bob",
  "ephemeralPublicKey": "<Base64 X.509 ECDH public key>",
  "signature": "<Base64 RSA signature of ephemeralPublicKey bytes>"
}
```

#### SESSION_ACK (новое в v0.4)
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

| Код | Описание |
|-----|----------|
| `INVALID_NAME` | Имя пользователя не соответствует требованиям |
| `NAME_TAKEN` | Имя уже используется другим клиентом |
| `INVALID_PUBLIC_KEY` | Публичный ключ не может быть распарсен |
| `RECIPIENT_OFFLINE` | Получатель не подключён |
| `EXPIRED` | Сообщение старше 30 секунд |
| `REPLAY` | Nonce уже встречался |
| `DECRYPTION_FAILED` | Не удалось расшифровать |
| `INVALID_FORMAT` | Невалидный формат сообщения |
| `INTERNAL_ERROR` | Внутренняя ошибка сервера |

---

## 7. Server Responsibilities

Сервер выполняет **только маршрутизацию**:
- Регистрация клиентов
- Поддержка реестра «имя → handler, publicKey»
- Проверка `timestamp` и `nonce` для replay protection
- Пересылка `INIT_SESSION`, `SESSION_ACK`, DM байт-в-байт
- Отправка ошибок инициатору при невалидных операциях

Сервер **не имеет доступа к**:
- Содержимому сообщений (зашифровано session_key)
- session_key (нет приватных ECDH-ключей)
- Эфемерным приватным ключам

---

## 8. Threat Model

### Защищённые угрозы

**Пассивный перехват провайдером** (защищён PSK):
- Атакующий видит TCP-пакеты, но не может прочитать JSON-метаданные

**Компрометация сервера** (защищён E2E + forward secrecy):
- Атакующий с доступом к серверу не может прочитать содержимое сообщений
- Атакующий не может подменить identity клиента (нет приватного ключа)

**MITM при handshake** (защищён RSA-подписями):
- Атакующий пытается подменить эфемерный ключ в INIT_SESSION/SESSION_ACK
- Получатель проверяет подпись долгоживущим RSA-публичным ключом
- Подделать подпись невозможно без приватного ключа отправителя

**Replay-атаки** (защищены timestamp + nonce):
- Атакующий повторяет старый перехваченный пакет
- Сервер отклоняет: либо timestamp устарел (>30 сек), либо nonce уже был

**Future compromise of identity keys** (защищено forward secrecy):
- Если завтра украдут долгоживущий RSA-приватный ключ Алисы
- Прошлые сессии остаются защищены
- Эфемерные приватные ключи давно уничтожены и не могут быть восстановлены

### Не защищённые угрозы (known limitations)

**Компрометация устройства клиента:**
- Атакующий с доступом к памяти процесса клиента видит session_key текущей
  сессии и долгоживущий RSA-приватный ключ
- Защита уровня OS (изоляция процессов) выходит за рамки протокола

**Per-message forward secrecy:**
- В v0.4 forward secrecy на уровне **сессии**, не каждого сообщения
- Компрометация session_key раскрывает все сообщения этой сессии
- Per-message FS (Double Ratchet как в Signal) — planned для v0.5+

**Метаданные при компрометации сервера:**
- Сервер видит кто кому пишет и когда
- Не видит содержимое, но связи между пользователями раскрыты
- Защита от metadata leakage — задача более сложных протоколов
  (например, mix networks)

**Утечки в swap-файл / memory dump:**
- session_key и приватные ключи могут попасть в swap или memory dump
- v0.4 не делает явное обнуление памяти (`Arrays.fill`)
- Planned для v0.5+

**Отказ в обслуживании (DoS):**
- Сервер не имеет rate limiting
- Атакующий может затопить сервер handshake-запросами
- Planned: rate limiting per-IP в v0.5+

**Аутентификация identity-ключей:**
- При первом подключении клиент доверяет публичному ключу, полученному
  от сервера через `GET_KEY` (TOFU — trust on first use)
- Безопасность: сервер мог бы подменить ключ при первой передаче
- Verification codes / safety numbers — planned для v0.6+

---

## 9. Cryptographic Constants

```
PSK_KEY_SIZE        = 256 bit
RSA_KEY_SIZE        = 2048 bit
ECDH_CURVE          = secp256r1 (P-256)
AES_IV_SIZE         = 12 bytes
AES_TAG_SIZE        = 16 bytes
NONCE_SIZE          = 16 bytes
TIMESTAMP_WINDOW    = 30 000 ms
NONCE_TTL           = 60 000 ms

PBKDF2_ITERATIONS   = 100 000
PBKDF2_SALT_SIZE    = 16 bytes
PBKDF2_KEY_SIZE     = 256 bit

HKDF_INFO           = "secure-chat-session"
HKDF_OUTPUT_SIZE    = 32 bytes
SESSION_HANDSHAKE_TIMEOUT = 10 000 ms
```

---

## 10. Backwards Compatibility

v0.4 **не совместим** с v0.3:
- Клиенты v0.3 шифруют сообщения через HybridCrypto (RSA+AES)
- Клиенты v0.4 шифруют через session_key (AES-GCM)
- Расшифровка между разными версиями невозможна

Будущие версии могут поддерживать negotiation версии при JOIN.

---

## 11. Roadmap

**v0.5:**
- Регистрация пользователей в БД
- JWT-аутентификация
- Rate limiting
- Зачёркивание session_key в памяти при завершении (zeroize)

**v0.6:**
- Verification codes / safety numbers
- Защита от MITM при первом обмене ключами

**v0.7:**
- WebSocket transport
- Веб-клиент
- Multiple device support

**v1.0:**
- Persistent message history
- Offline message delivery
- Presence (online/offline status)

**Backlog:**
- Per-message forward secrecy (Double Ratchet)
- Group chat (MLS)
- Platform-specific KeyStorage (Windows Credential Manager и т.д.)
- SDK на Maven Central
- Переход с SHA256withRSA на Ed25519 для подписей

---

## 12. References

- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HKDF
- [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) — PKCS #5 (PBKDF2)
- [SEC 2](https://www.secg.org/sec2-v2.pdf) — Recommended Elliptic Curve Parameters (secp256r1)
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) — AES-GCM
- [Signal Protocol](https://signal.org/docs/) — inspiration for forward secrecy design