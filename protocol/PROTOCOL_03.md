# Secure Chat Protocol Specification

**Version:** 0.3 (Draft)
**Status:** In development
**Date:** 2026-05-13

---

## 1. Overview

Secure Chat Protocol (SCP) — это прикладной протокол поверх TCP для обмена
сообщениями между несколькими клиентами через центральный сервер.

Версия 0.3 добавляет **end-to-end шифрование** через гибридную схему RSA+AES
и защиту от replay-атак. Шифрование канала из v0.2 остаётся как внешний слой.

### Возможности v0.3

- Подключение клиента по имени со структурированным handshake
- Регистрация публичного RSA-ключа клиента на сервере
- Получение публичного ключа другого клиента через сервер
- **End-to-end шифрование сообщений** — сервер не может прочитать содержимое
- **Защита от replay-атак** через timestamp + nonce-tracking
- Внешний слой шифрования канала через AES-PSK (из v0.2)
- Унифицированный JSON-формат во всех направлениях

### Слои защиты

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

Внешний слой (PSK) защищает от пассивного перехвата в сети.
Внутренний слой (E2E) защищает от чтения сервером.

### Ограничения v0.3

- **Нет верификации публичных ключей.** Сервер выдаёт ключ собеседника без
  возможности проверить его подлинность. Скомпрометированный сервер может
  подменить ключ (MITM-атака на E2E). Решение — verification codes — в v0.6+.
- **Нет forward secrecy.** Если приватный ключ украдут, прошлые сообщения
  расшифровываются. Решается через ephemeral keys или Double Ratchet.
- **Приватный ключ в памяти.** Каждый запуск — новая пара ключей.
  Persistence будет в v0.4.
- **Сервер видит метаданные.** Кто, кому, когда. Защита требует mix-networks.
- **Один общий PSK для канала.** Знание PSK = разрешение подключиться.
  Аутентификация клиентов через JWT — в v0.5.
- Сообщения не сохраняются: если получатель офлайн, сообщение теряется.

---

## 2. Transport

| Параметр | Значение |
|----------|----------|
| Транспортный протокол | TCP |
| Порт по умолчанию | 5000 |
| Кодировка | UTF-8 |
| Разделитель сообщений | `\n` (LF) |
| Модель | Клиент-сервер, один сервер на N клиентов |

Каждое сообщение — одна строка, оканчивающаяся `\n`.
Содержимое строки — Base64-кодированный шифротекст PSK-слоя.

---

## 3. Cryptography

### 3.1. Symmetric (transport layer)

- **Cipher:** AES в режиме GCM
- **Key size:** 256 bit
- **IV size:** 96 bit (12 байт)
- **Auth tag:** 128 bit (16 байт)
- **Java cipher string:** `AES/GCM/NoPadding`

PSK-ключ загружается из `application.properties` или переменной окружения
`SCP_PSK`. Идентичен на сервере и всех клиентах.

### 3.2. Asymmetric (E2E layer)

- **Cipher:** RSA
- **Key size:** 2048 bit
- **Padding:** OAEP с SHA-256 и MGF1
- **Java cipher string:** `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

Каждый клиент генерирует свою пару ключей при старте. Публичный ключ
отправляется серверу в JOIN. Приватный ключ **никогда не покидает клиента**.

### 3.3. Hybrid encryption (E2E messages)

Для каждого сообщения, отправляемого конкретному получателю:

1. Сгенерировать одноразовый AES-256-ключ через `KeyGenerator`
2. Зашифровать plaintext через AES-GCM с этим ключом → `aesPayload`
3. Зашифровать AES-ключ через RSA публичным ключом получателя → `rsaKey`
4. Склеить: `payload = rsaKey (256B) || aesPayload`
5. Закодировать в Base64

Получатель:

1. Декодировать Base64 → байты payload
2. Первые 256 байт → `rsaKey` (зашифрованный AES-ключ)
3. Остальное → `aesPayload` (зашифрованное сообщение)
4. Расшифровать `rsaKey` через RSA своим приватным ключом → AES-ключ
5. Расшифровать `aesPayload` через AES-GCM с этим ключом → plaintext

### 3.4. Replay protection

Каждое `SEND_MESSAGE` содержит:

- `timestamp` — Unix epoch в миллисекундах
- `nonce` — 16 случайных байт в Base64

Сервер проверяет:

- `|now - timestamp| < 30 секунд` — иначе `ERROR: EXPIRED`
- `nonce` не встречался в последние 60 секунд — иначе `ERROR: REPLAY`

Сервер хранит nonces в `ConcurrentHashMap<String, Long>` (nonce → expiration).
Очистка устаревших записей — раз в минуту фоновой задачей.

### 3.5. Security guarantees

| Угроза | Защита в v0.3 |
|--------|---------------|
| Пассивный перехват в сети | ✅ PSK AES-GCM |
| Изменение шифротекста | ✅ GCM auth tag (оба слоя) |
| Чтение содержимого сервером | ✅ E2E через RSA+AES |
| Replay-атака | ✅ timestamp + nonce-tracking |
| Спуфинг отправителя | ✅ Сервер подставляет имя из контекста |
| MITM при выдаче ключа | ❌ Решается в v0.6+ |
| Компрометация приватного ключа | ❌ Forward secrecy в будущем |
| DDoS на сервер | ❌ Rate limiting в v0.5+ |
| Анализ метаданных сервером | ❌ Вне рамок проекта |

---

## 4. Wire format

### 4.1. Outer layer (PSK)

```
Base64( IV (12B) || ciphertext (N) || authTag (16B) ) \n
```

После Base64-декодирования и AES-GCM-расшифровки внутри — JSON-сообщение.

### 4.2. E2E payload (внутри SEND_MESSAGE)

```
Base64( RSA_encrypted_AES_key (256B) || AES_encrypted_message (N) )
```

Передаётся как строковое поле `e2ePayload` в JSON.

---

## 5. JSON Message Schema

### 5.1. Client → Server (ClientMessage)

| Поле | Тип | Обязательное | Описание |
|------|-----|--------------|----------|
| `commandType` | enum | да | `JOIN`, `SEND_MESSAGE`, `GET_KEY`, `QUIT` |
| `username` | string | для JOIN | Имя пользователя |
| `publicKey` | string | для JOIN | RSA-публичный ключ в Base64 (X.509) |
| `toClientName` | string | для SEND_MESSAGE, GET_KEY | Имя цели |
| `e2ePayload` | string | для SEND_MESSAGE | E2E-шифрованное сообщение в Base64 |
| `timestamp` | long | для SEND_MESSAGE | Unix epoch ms |
| `nonce` | string | для SEND_MESSAGE | 16 случайных байт в Base64 |

**Изменения относительно v0.2:**
- В JOIN добавлено `publicKey`
- Добавлен `commandType: GET_KEY`
- В SEND_MESSAGE поле `message` заменено на `e2ePayload`
- В SEND_MESSAGE добавлены `timestamp` и `nonce`

### 5.2. Server → Client (ServerMessage)

| Поле | Тип | Обязательное | Описание |
|------|-----|--------------|----------|
| `messageType` | enum | да | `DM`, `DELIVERED`, `ERROR`, `SYSTEM`, `PUBLIC_KEY` |
| `fromClientName` | string | для DM | Имя отправителя |
| `e2ePayload` | string | для DM | Зашифрованное сообщение (без изменений) |
| `text` | string | для SYSTEM, ERROR | Текст для отображения |
| `errorCode` | enum | для ERROR | Код ошибки |
| `username` | string | для PUBLIC_KEY | Имя клиента, чей ключ |
| `publicKey` | string | для PUBLIC_KEY | RSA-публичный ключ в Base64 |

**Изменения относительно v0.2:**
- Добавлен `messageType: PUBLIC_KEY`
- В DM поле `text` заменено на `e2ePayload`

---

## 6. Commands

### 6.1. JOIN

**Направление:** клиент → сервер
**Когда:** первое сообщение после установки TCP-соединения

```json
{
  "commandType": "JOIN",
  "username": "Alice",
  "publicKey": "MIIBIjANBgkqhkiG9w0B..."
}
```

**Поведение сервера:**

1. Проверить валидность `username` (см. §8)
2. Проверить, что имя не занято
3. Распарсить `publicKey` (Base64 → X.509 → RSAPublicKey)
4. Зарегистрировать: имя → handler, имя → publicKey
5. Отправить `SYSTEM` с приветствием

**Ошибки:** `INVALID_NAME`, `NAME_TAKEN`, `INVALID_PUBLIC_KEY`

### 6.2. GET_KEY

**Направление:** клиент → сервер
**Когда:** перед отправкой первого сообщения собеседнику

```json
{
  "commandType": "GET_KEY",
  "toClientName": "Bob"
}
```

**Поведение сервера:**

1. Найти `Bob` в реестре публичных ключей
2. Если найден → `PUBLIC_KEY` с username, publicKey
3. Если нет → `ERROR: RECIPIENT_OFFLINE`

Клиент кеширует полученный ключ локально, чтобы не запрашивать повторно.

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

**Поведение сервера:**

1. Проверить replay protection:
    - `|now - timestamp| < 30000ms` иначе `ERROR: EXPIRED`
    - `nonce` не в кеше иначе `ERROR: REPLAY`
    - Добавить `nonce` в кеш с TTL 60 сек
2. Найти получателя
3. Если найден → передать `DM` с `e2ePayload` **без изменений**
4. Отправителю → `DELIVERED`
5. Если не найден → `ERROR: RECIPIENT_OFFLINE`

**Важно:** `fromClientName` из контекста хендлера, не из JSON — защита от спуфинга.
Сервер **не расшифровывает** `e2ePayload`.

### 6.4. QUIT

```json
{"commandType": "QUIT"}
```

Удалить из реестра подключённых и из реестра ключей, закрыть соединение.

---

## 7. Error codes

| errorCode | Когда |
|-----------|-------|
| `INVALID_NAME` | Имя не прошло валидацию |
| `NAME_TAKEN` | Имя уже занято |
| `INVALID_PUBLIC_KEY` | Публичный ключ не парсится |
| `RECIPIENT_OFFLINE` | Получатель не подключён |
| `EXPIRED` | Timestamp вне окна |
| `REPLAY` | Nonce уже встречался |
| `DECRYPTION_FAILED` | Не удалось расшифровать PSK-слой |
| `INVALID_FORMAT` | JSON не парсится |
| `INTERNAL_ERROR` | Серверная ошибка |

---

## 8. Name validation

- Длина: 1–32 UTF-8 символа
- Допустимые: латиница, кириллица, цифры, `_`, `-`
- Regex: `^[\p{L}\p{N}_-]{1,32}$`
- Не может начинаться с `_` или `-`

---

## 9. Connection lifecycle

```
КЛИЕНТ                                        СЕРВЕР
  |                                             |
  |--- TCP connect ---------------------------->|
  |                                             |  accept, новый Handler
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

`enc_psk(...)` — AES-GCM-шифрование через PSK по §3.1.

---

## 10. Privacy properties (Threat Model)

### От пассивного перехвата в сети

- Содержимое: ✅ защищено (двойное шифрование)
- Метаданные: ✅ защищены PSK-слоем
- Факт коммуникации с сервером: ❌ виден

### От активного MITM в сети

- Содержимое: ✅ защищено (GCM auth tag)
- Подмена пакетов: ✅ обнаруживается

### От недобросовестного сервера

- Содержимое: ✅ защищено E2E
- Метаданные (кто/кому/когда): ❌ сервер видит всё
- Подмена публичного ключа: ❌ возможна (решение в v0.6+)

### От компрометации клиента

- Чужие сообщения: ✅ защищены
- Прошлые свои сообщения: ❌ расшифровываются (нет forward secrecy)

---

## 11. Backward compatibility

v0.3 не совместим с v0.2.

---

## 12. Versioning roadmap

| Версия | Статус | Изменения |
|--------|--------|-----------|
| v0.1 | ✅ Done | Базовый TCP-чат без шифрования |
| v0.2 | ✅ Done | AES-GCM шифрование канала, JSON-протокол |
| **v0.3** | **🚧 In progress** | **E2E через RSA+AES, replay protection** |
| v0.4 | Planned | Persistent key storage, forward secrecy |
| v0.5 | Planned | JWT-аутентификация, rate limiting |
| v0.6 | Planned | Key verification, trust-on-first-use |
| v0.7 | Planned | WebSocket, веб-клиент |
| v1.0 | Planned | История, доставка офлайн, presence |

---

## 13. Known issues and limitations (v0.3)

1. **MITM при выдаче публичных ключей.** Сервер может подменить ключ.
2. **Нет forward secrecy.** Компрометация ключа компрометирует прошлое.
3. **Приватный ключ не сохраняется.** Каждый запуск — новая пара.
4. **Сервер видит метаданные.** От кого, кому, когда.
5. **Один общий PSK.** Любой обладатель PSK может подключиться.
6. **Nonce-кеш в памяти.** Перезапуск обнуляет защиту на минуту.
7. **Сообщения теряются** при оффлайне получателя.
8. **Нет аутентификации.** Подключение под любым свободным именем.