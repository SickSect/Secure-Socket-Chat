# Гайд по криптографии Secure Chat — с нуля до ратчета

> **Для новичка.** Здесь объясняется **как устроено в этом проекте**: роль
> каждого алгоритма, его место в коде, как он работает и на что влияет.
> Все примеры — реальные фрагменты из этого репозитория.
>
> Читать в порядке разделов: сначала **§1–§2** (карта и шпаргалка), потом
> **§3** (разбор алгоритмов), **§4–§5** (ключи и жизнь сообщения),
> **§7–§8** (запоминание и глоссарий).

---

## §1. Одна большая карта: путь сообщения `@bob привет`

Когда ты пишешь `@bob привет`, происходит **5 этапов**. Каждый этап —
свой файл, свой алгоритм:

| # | Этап | Файл | Главный метод | Алгоритм |
|---|------|------|---------------|----------|
| 0 | Логин: пароль → JWT | `auth/LocalAuthProvider.java`, `auth/JwtService.java` | `authenticate()` / `generate()` | BCrypt + HMAC (JWT) |
| 1 | Сервер присылает ключ Боба | `client/ChatClientCore.java` | `handlePUBLIC_KEY()` → `trustStore.verify()` | SHA-256 (fingerprint), TOFU |
| 2 | Handshake: общий секрет | `crypto/EcdhCrypto.java`, `crypto/SessionCrypto.java` | `computeSharedSecret()` / `derive()` | ECDH P-256 + HKDF + RSA-подпись |
| 3 | Шифрование сообщения | `crypto/SessionCrypto.java`, `client/SessionContext.java` | `beginSend()` → `encrypt()` | HMAC-цепочка + AES-256-GCM |
| 4 | Приём на другой стороне | `client/SessionContext.java` | `planReceive()` → `decrypt()` → `commitReceive()` | GCM-проверка + возможная DH-ротация |

Поверх **всех** этапов работает транспорт **TLS 1.3** (`TlsClientContextFactory`,
`TlsServerContextFactory`) — без него ни один байт не уходит в сеть.

Один ключевой принцип, который связывает всё: **каждый алгоритм отвечает ровно
за одну вещь**. Не за две. Это и делает систему понятной.

---

## §2. Шпаргалка: роль каждого алгоритма

| Алгоритм | Простыми словами | Где в коде | Без него сломалось бы |
|----------|------------------|------------|------------------------|
| **SHA-256** | «Отпечаток»: из чего угодно делает32-байтовый отсчёт | `SessionCrypto.transcriptHash()`, `KeyFingerprint.hex()` | Нельзя было бы сравнивать ключи и привязывать handshake к именам |
| **HMAC-SHA256** | «Печать с секретом»: односторонняя цепочка ключей | `SessionCrypto.hmac()`, `kdfCk()`, `kdfRk()` | Каждое сообщение шифровалось бы одним ключом (пункт 2 не закрыт) |
| **HKDF** | «Фабрика ключей»: из одного секрета выводит сколько угодно разных ключей | `HkdfCrypto.derive()`, `SessionCrypto.derive()` | Пришлось бы использовать один ECDH-секрет и для подписей, и для шифрования |
| **AES-256-GCM** | «Сейф с замком и сургучом»: шифрует + проверяет целостность | `SessionCrypto.encrypt()/decrypt()`, `AesCrypto` | Текст был бы виден, а подделку невозможно было бы заметить |
| **ECDH P-256** | «Обмен секретом на виду у всех»: двое получают общий секрет, не показывая его | `EcdhCrypto.computeSharedSecret()` | Не было бы общего секрета → нечего было бы шифровать E2E |
| **RSA-2048 + SHA256withRSA** | «Нотариус»: подписью доказывает, что *этот* ключ принадлежит *тому*, кто подписал | `RsaSignature.sign()/verify()` | Сервер мог бы подделать handshake от чужого имени |
| **PBKDF2** | «Парольный замок»: из пароля делает ключ AES-256 (медленно,600 000 раз) | `PbeUtil.encrypt()/decrypt()` | Приватный RSA-ключ лежал бы на диске открытым |
| **BCrypt** | «Необратимый хеш пароля» с самоподстройкой сложности | `SecurityConfig.passwordEncoder()`, `LocalAuthProvider` | Пароли в БД можно было бы прочитать |
| **JWT (HS256 = HMAC)** | «Пропуск на вход»: подписанный сервером талон с именем и сроком | `JwtService.generate()/validateAndGetUsername()` | Каждый запрос пришлось бы логинить заново, имя в JOIN можно было бы подделать |
| **TLS 1.3** | «Бронепоезд» между клиентом и сервером | `TlsClientContextFactory`, `TlsServerContextFactory` | Сетевой атакующий видел бы всё, включая метаданные и ключи |

**Запомни связку:** SHA-256 и HMAC — «односторонние функции» (назад нельзя),
AES — «обратимая операция с ключом», ECDH/RSA — «математика парных ключей»,
HKDF/PBKDF2/BCrypt — «производные ключи из слабого входа» (пароля или шума).

---

## §3. Разбор алгоритмов — с примерами из нашего кода

### 3.1 SHA-256 — «отпечаток»

**Что делает:** берёт любые данные → выдаёт32 байта, по которым нельзя
восстановить вход и которые меняются при изменении **хотя бы одного** байта.

**Где у нас — два места:**

1) **Транскрипт handshake** — «снимок» всех переговоров, чтобы ключи были
привязаны к именам и обоим эфемерным ключам
(`app/src/main/java/org/ugina/crypto/SessionCrypto.java`):

```java
public static byte[] transcriptHash(String initiator, String responder,
        byte[] initiatorEphemeralPub, byte[] responderEphemeralPub) {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    updateLengthPrefixed(digest, (INFO_PREFIX + "/transcript").getBytes(...));
    updateLengthPrefixed(digest, initiator.getBytes(...));   // имя инициатора
    updateLengthPrefixed(digest, responder.getBytes(...));   // имя получателя
    updateLengthPrefixed(digest, initiatorEphemeralPub);     // ключ A
    updateLengthPrefixed(digest, responderEphemeralPub);     // ключ B
    return digest.digest();
}
```

**На что влияет:** если сервер подменит имя или ключ в handshake — транскрипт
изменится → выведенные ключи у сторон **не совпадут** → `SESSION_CONFIRM`
отклонится. Это и есть «привязка к транскрипту».

2) **Fingerprint ключа** для TOFU (`crypto/KeyFingerprint.java`):

```java
public static String hex(PublicKey publicKey) {
    MessageDigest digest = sha256();
    updateLengthPrefixed(digest, LABEL.getBytes(UTF_8));  // "secure-chat/v2/key-fingerprint"
    updateLengthPrefixed(digest, encoded);                // байты публичного ключа
    return HexFormat.of().formatHex(digest.digest());     // 64 hex-символа
}
```

**На что влияет:** это то самое число, которое лежит в
`~/.secure-chat/known-peers.tsv` и по которому TOFU ловит подмену ключа.

---

### 3.2 HMAC-SHA256 — «цепочка ключей» (ядро пункта 2)

**Что делает:** `HMAC(ключ, данные) →32 байта`. Обратно **невозможно**:
зная результат, не получишь ни ключ, ни данные. Именно это свойство
заставляет ключи «течь только вперёд».

**Где у нас:** `SessionCrypto` — две функции ратчета:

```java
// kdfCk — один шаг симметричной цепочки (КАЖДОЕ сообщение):
//   из текущей цепочки C_n получаем ключ сообщения и цепочку C_{n+1}
public static ChainStep kdfCk(byte[] chainKey) {
    byte[] messageKey   = hmac(chainKey, "secure-chat/v3/msg-key");
    byte[] nextChainKey = hmac(chainKey, "secure-chat/v3/next-chain");
    return new ChainStep(messageKey, nextChainKey);
}

// kdfRk — DH-ротация (раз в «ход»): новый корень + новая цепочка
public static RatchetStep kdfRk(byte[] rootKey, byte[] dhSecret, String direction) {
    byte[] prk = hmac(rootKey, dhSecret);                        // корень «перемешан» со свежим DH
    byte[] newRoot = hmac(prk, ".../ratchet/" + direction + "/root");
    byte[] chainKey = hmac(prk, ".../ratchet/" + direction + "/chain");
    return new RatchetStep(newRoot, chainKey);
}
```

**На что влияет:**
- `kdfCk` → **пер-месседжный forward secrecy**: утечка ключа сообщения №5 не
  открывает ни №4 (назад нельзя), ни... ключ №5 — это один текст;
- `kdfRk` → **break-in recovery**: украв состояние целиком, атакующий всё
  равно не откроет сообщения после следующей ротации (нет приватной части
  свежего ключа собеседника);
- метки направления `"i2r"` / `"r2i"` → обе стороны считают **одинаковую**
  последовательность корней, иначе цепочки разошлись бы навсегда.

**Аналогия для запоминания:** одноразовый ключ от ячейки: закрыл — выбросил
назад не вернёшь; раз в ход вас с соседом меняют ключи полностью.

---

### 3.3 HKDF — «фабрика ключей»

**Что делает:** из одного «сырого» секрета (от ECDH) выводит нужное
количество **независимых** ключей. Две ступени (`crypto/HkdfCrypto.java`):

```java
public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
    byte[] prk = extract(ikm, salt);                 //1) «солью» из ECDH-шума делаем PRK
    return expand(prk, info.getBytes(UTF_8), length); // 2) по метке info нарезаем ключи
}
```

- `extract` = `HMAC(salt, ikm)` — сглаживает слабый/нестабильный вход;
- `expand` = цепочка `HMAC(PRK, info || counter)` — метка `info` гарантирует,
  что разные ключи **не пересекутся**: `"…/root"`, `"…/initiator-confirm"`,
  `"…/responder-confirm"` — это разные выходы одной фабрики.

**Где у нас:** `SessionCrypto.derive()` на handshake:

```java
byte[] rootKey          = HkdfCrypto.derive(sharedSecret, transcriptHash, "…/root", 32);
byte[] initiatorConfirm = HkdfCrypto.derive(sharedSecret, transcriptHash, "…/initiator-confirm", 32);
byte[] responderConfirm = HkdfCrypto.derive(sharedSecret, transcriptHash, "…/responder-confirm", 32);
```

**На что влияет:** `rootKey` — «банкетный зал», из него живёт весь ратчет;
`confirm`-теги — доказательство, что обе стороны вывели одинаковое (проверяется
в `SessionContext.completeAsInitiator()` через `constantTimeEquals`).

---

### 3.4 AES-256-GCM — «сейф с сургучом»

**Что делает:** симметричное шифрование (один ключ и туда, и обратно) +
встроенный **аутентифицирующий тег**: если байт подделан — расшифровка
падает. Три обязательных ингредиента:

- **ключ** (256 бит) — из ратчета (§3.2);
- **IV/nonce** (12 байт) — случайный на каждое сообщение, чтобы два
  сообщения под одним ключом не получили один шифртекст;
- **AAD** — данные, которые шифруются *не сами*, но **включаются в тег**:
  их нельзя тихо изменить.

**Где у нас — два места:**

1) Шифрование сообщений v3 (`SessionCrypto.encrypt()`):

```java
byte[] iv = new byte[12];
RANDOM.nextBytes(iv);                                    // случайный IV
byte[] aad = aad(flags, newRatchetPublicKey,             // ← что защищаем от подделки:
        sender, recipient, sequence, chainIndex);        //   флаг, ключ ратчета,
cipher.init(Cipher.ENCRYPT_MODE, messageKey,             //   имена, seq, индекс цепочки
        new GCMParameterSpec(128, iv));
cipher.updateAAD(aad);
byte[] cipherText = cipher.doFinal(plainText.getBytes(UTF_8));
// в кадр: [ver][flags][ratchetPub?][seq][chainIdx][iv][cipherText + тег]
```

2) Общая утилита `AesCrypto` (используется legacy-гидридным кодом
`HybridCrypto` и тестами; сообщения v3 шифруются напрямую в `SessionCrypto`).

**На что влияет:** AAD — это то, почему **сервер-ретранслятор не может**
переписать `sender`, выкинуть флаг ратчета или подменить `sequence`: тег
перестанет сходиться. Случайный IV — почему повторное использование ключа
не ведёт к катастрофе. Тег длиной128 бит — почему подделать сообщение
«вслепую» нельзя.

---

### 3.5 ECDH (P-256) — «обмен секретом»

**Что делает:** у Алисы и Боба по паре ключей. Они обмениваются **только
публичными** частями и локально вычисляют **одинаковый** секрет. Наблюдатель
видит публичные ключи, но секрет не посчитает (задача эллиптической кривой:
`log` по кривой не считается).

**Где у нас** (`crypto/EcdhCrypto.java`):

```java
public static byte[] computeSharedSecret(PrivateKeyHolder ownPrivateKey, PublicKey peerPublicKey) {
    validatePublicKey(peerPublicKey);                  // только P-256, никакого даунгрейда
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
    keyAgreement.init(ownPrivateKey.key());
    keyAgreement.doPhase(peerPublicKey, true);
    return keyAgreement.generateSecret();              // ← сырой общий секрет (нельзя использовать напрямую!)
}
```

**Где у нас вызывается — два разных смысла:**

| Смысл | Где | Что даёт |
|-------|-----|----------|
| **Handshake** (один раз) | `ChatClientCore.handleSessionAck()` / `handleInitSessionAsync()` | Общий `sharedSecret` → HKDF → `rootKey` (§3.3) |
| **DH-ротация** (раз в ход) | `SessionContext.beginSend()` (первый шаг) и `planReceive()` (шаг ратчета) | Свежий `dhSecret` → `kdfRk` → новый корень и цепочки |

**Важно для новичка:** сырой ECDH-секрет **нельзя шифровать им напрямую** —
в комментарии кода прямо сказано `// THIS IS RAW ECDH SECRET! NOT A FINAL KEY!`.
Он всегда идёт в HKDF/`kdfRk`.

**Проверка точки** (защита от «кривых» ключей) — `EcdhCrypto.publicKeyFromRaw()`:

```java
// y² = x³ + a·x + b (mod p) — точка обязана лежать на secp256r1
if (!left.equals(right)) {
    throw new CryptoException("EC point is not on the P-256 curve", null);
}
```

**На что влияет:** без валидации атакующий мог бы прислать вырожденную
точку и «подсунуть» свой секрет вместо Бобова.

---

### 3.6 RSA-2048 + SHA256withRSA — «нотариус»

**Что делает:** у каждого пользователя **долгоживущая** пара RSA.
Приватным ключом подписывает — публичным проверяет. Подпись **привязана
к содержимому**: изменил хоть байт — проверка не пройдёт.

**Где у нас** (`crypto/RsaSignature.java`):

```java
public static byte[] sign(byte[] data, PrivateKey privateKey) {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);
    return signature.sign();
}
```

**Что именно подписывается** — канонический payload (`SessionCrypto.signingPayload`):

```java
"secure-chat/v3/handshake" || role || signer || peer || ephemeralPublicKey
//                         роль   кто      кому     эфемерный ключ
```

Пример вызова (`ChatClientCore.handleSessionAck()`):

```java
byte[] toVerify = SessionCrypto.signingPayload("ack", peerName, ownName, peerEphemeralBytes);
if (!RsaSignature.verify(toVerify, signatureBytes, peerRsaPublic)) {
    context.failHandshake("Invalid signature");      // ← подделать handshake нельзя
}
```

**На что влияет:**
- `role` в подписи → захваченный `INIT_SESSION` нельзя переиграть как `SESSION_ACK`;
- `signer || peer` → нельзя подставить чужого собеседника (защита от
  cross-peer replay / identity misbinding);
- эфемерный ключ в подписи → нельзя подменить ключ ECDH в handshake.

**Почему RSA, а не ECDH, для подписей:** ECDH умеет только *договориться о
секрете*; подписывать он не умеет. Это разные инструменты.

---

### 3.7 PBKDF2 — «парольный замок приватного ключа»

**Что делает:** из **слабого** пароля человека делает крепкий ключ AES.
Слабость компенсируется **работой**: `PBKDF2WithHmacSHA256` крутит
HMAC **600 000 раз** — перебор пароля становится дорогим.

**Где у нас** (`crypto/PbeUtil.java`):

```java
private static final byte[] MAGIC_V2 = {'S', 'C', 'K', '1'};   // версия формата
private static final int V2_ITERATIONS = 600_000;               // OWASP
private static final int SALT_LENGTH = 16;                      // уникальная соль на файл
// encrypt: MAGIC || salt || iv || AES-256-GCM(приватный ключ)
```

**На что влияет:** файл `~/.secure-chat/<user>.key` (приватный RSA-ключ)
хранится в `FileBasedKeyStorage.save()` именно так: без пароля его не
прочитать; `SALT` не даёт одинаковым паролям давать одинаковые ключи;
`MAGIC` позволяет потом поднять число итераций, не ломая старые файлы;
`cipher.updateAAD(MAGIC_V2)` — версию нельзя подделать.

---

### 3.8 BCrypt — «хеширование паролей»

**Что делает:** односторонне хеширует пароль с **самоподстройкой** (cost) и
встроенной солью. Обратно — никогда.

**Где у нас:**

```java
// config/SecurityConfig.java — бин кодировщика
public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

// auth/LocalAuthProvider.java — регистрация и вход
user.setPasswordHash(passwordEncoder.encode(password));          // регистрация
...
if (!passwordEncoder.matches(safePassword, user.getPasswordHash())) // вход
    throw new AuthenticationException("Invalid username or password");
// а для несуществующего юзера — фейковая проверка, чтобы уравнять время ответа:
passwordEncoder.matches(safePassword, dummyPasswordHash);
```

**На что влияет:** утечка БД не отдаёт пароли; фейковая проверка
(`dummyPasswordHash`) прячет, *зарегистрирован* пользователь или нет, от
тайминг-атаки.

---

### 3.9 JWT (HS256) — «пропуск на вход»

**Что делает:** после логина сервер выдаёт подписанный талон
`header.payload.signature`. Дальше клиент присылает его в каждом запросе и
на `JOIN` в чат. Проверяется **подпись HMAC** (то есть HMAC-SHA256 из §3.2!),
срок и issuer.

**Где у нас** (`auth/JwtService.java`):

```java
return Jwts.builder()
        .issuer("secure-chat")            // кто выпустил
        .subject(username)                // КТО (из него берётся имя в чате!)
        .issuedAt(Date.from(now))
        .expiration(Date.from(expiry))    // срок жизни (60 мин)
        .signWith(signingKey)             // HMAC-SHA256 секретом сервера
        .compact();
```

Fail-safe секрет (важно!):

```java
// Если JWT_SECRET пустой/короткий/известный публичный — генерируем случайный:
if (bytes.length >=32 && !trimmed.equals(KNOWN_INSECURE_SECRET)) return bytes;
new SecureRandom().nextBytes(random);   // токены перестанут работать после рестарта —
return random;                          // это ЛУЧШЕ, чем подделываемый секрет
```

**На что влияет:** в `ChatHandler` имя в `JOIN` берётся из проверенного JWT,
а не из полей клиента — иначе можно было бы писать от чужого имени.
`JWT_SECRET` живёт в `.env` (не в git).

---

### 3.10 TLS 1.3 — «бронепоезд»

**Что делает:** шифрует и аутентифицирует **весь** транспорт: REST (8443) и
порт чата (5000). Это защита **от сети**, а не от сервера (сервер — точка
терминирования, ему видно всё после расшифровки; от него как раз E2E).

**Где у нас** (пример из `ChatClientCore.connect()`):

```java
sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
SSLParameters sslParameters = sslSocket.getSSLParameters();
sslParameters.setProtocols(new String[]{"TLSv1.3"});              // только1.3
sslParameters.setEndpointIdentificationAlgorithm("HTTPS");        // проверка имени в сертификате!
sslSocket.setSSLParameters(sslParameters);
sslSocket.startHandshake();
```

Серверная сторона — `TlsServerContextFactory` (keystore `certs/server-keystore.p12`),
клиентская — `TlsClientContextFactory` (truststore `certs/client-truststore.p12`).
Оба **падают с ошибкой**, если сертификат/пароль не заданы, — без TLS ни один
байт не уходит (fail-closed).

**На что влияет:** `endpointIdentificationAlgorithm("HTTPS")` — то, почему
MITM с чужим сертификатом невозможен; `setProtocols` — почему TLS1.2
отклоняется (`protocol_version`).

---

## §4. Иерархия ключей: кто кого порождает и где живёт

```
ПАРОЛЬ ПОЛЬЗОВАТЕЛЯ ──BCrypt──► хеш в PostgreSQL (password_hash)
        │
        └──PBKDF2(600k)──► AES-ключ ──шифрует──► ~/.secure-chat/<user>.key
                                                   (приватный RSA-ключ, SCK1)

JWT_SECRET (.env) ──HMAC──► JWT (талон на60 мин)

ДОЛГОЖИВУЩИЙ RSA (identity):
   публичный ──► PostgreSQL (users.public_key) ──GET_KEY──► публикуется пирам
   приватный ──► подписывает handshake (§3.6)

HANDSHAKE (один раз на сессию):
   ECDH(эфемерные пары) ──► sharedSecret
   sharedSecret + transcriptHash ──HKDF──► rootKey + confirm-теги

РАТЧЕТ (живёт в SessionContext, в памяти):
   rootKey ──kdfRk (DH-ротация)──► новый rootKey + chainKey
   chainKey ──kdfCk (каждое сообщение)──► messageKey (AES-256) + следующая chainKey
   messageKey ──AES-GCM──► шифртекст сообщения
```

Таблица «что где хранится»:

| Материал | Файл/место | Срок жизни |
|----------|-----------|------------|
| Пароль (хеш) | PostgreSQL `users.password_hash` | Пока аккаунт существует |
| Приватный RSA-ключ | `~/.secure-chat/<user>.key` (шифр. PBKDF2) | Постоянно, пока не перевыпущен |
| Публичный RSA-ключ | PostgreSQL `users.public_key` | Пока не перевыпущен |
| `JWT_SECRET` | `.env` (gitignored) | Пока задан |
| Серверный TLS-ключ | `certs/server-keystore.p12` | Годен для dev |
| Закреплённые ключи пиров | `~/.secure-chat/known-peers.tsv` | Пока не пере-trust'нуты |
| `rootKey`, цепочки, ратчет-пара | Память `SessionContext` | Одна сессия (idle30 мин / abs24 ч) |
| `messageKey` | Память, один раз на сообщение | Один кадр, потом `destroy()` |

---

## §5. Жизнь одного сообщения — по шагам с кодом

### Шаг 0. Логин (один раз)

```
ввод пароля → LocalAuthProvider.authenticate()
           → BCrypt.matches(пароль, хеш)          [§3.8]
           → JwtService.generate(username)         [§3.9]
           → JWT возвращён клиенту
```

### Шаг 1. Первое сообщение → handshake

```
A: @bob привет
 └─ ChatClientCore.sendMessage()
     └─ getOrEstablishSession("bob")
         └─ instantiateHandshake("bob")
             ├─ requestPublicKey("bob") ──GET_KEY──► сервер
             │    └─ handlePUBLIC_KEY():
             │         trustStore.verify("bob", ключ)        ← TOFU (§6)
             ├─ EcdhCrypto.generateKeyPair()                 ← эфемерная пара A
             ├─ toSign = signingPayload("init", A, B, ephA)  [§3.6]
             ├─ RsaSignature.sign(toSign, privateKeyA)
             └─ ──INIT_SESSION(ephA, подпись)──► B
```

Сторона B (`handleInitSessionAsync`):

```java
PublicKey peerEphemeralPub = EcdhCrypto.publicKeyFromBase64(msg.ephemeralPublicKey);
byte[] toVerify = SessionCrypto.signingPayload("init", peerName, ownName, peerEphemeralBytes);
if (!RsaSignature.verify(toVerify, signature, peerRsaPublicKey)) { ... }   // нотариус проверил

sharedSecret = EcdhCrypto.computeSharedSecret(ownEphemeral, peerEphemeral); // общий секрет [§3.5]
SessionCrypto.DerivedKeys keys = SessionCrypto.derive(
        sharedSecret, peerName, ownName, peerEphemeralBytes, ownEphemeralBytes);
        // → rootKey + confirm-теги (HKDF)                              [§3.3]
byte[] confirmation = context.completeAsResponder(keys);
// ──SESSION_ACK(ephB, подписьB, confirmationB)──► A
```

Сторона A (`handleSessionAck`) проверяет подпись B и **confirmation** —
доказательство, что B вывел **тот же** rootKey:

```java
if (!SessionCrypto.constantTimeEquals(keys.responderConfirm(), peerConfirmation)) {
    throw new CryptoException("Responder key confirmation does not match", null);
}
// ──SESSION_CONFIRM──► B  → обе стороны READY
```

### Шаг 2. Шифрование (отправка)

```java
// ChatClientCore.sendMessage()
SessionContext.SendTicket ticket = session.beginSend();
//   beginSend():
//     sendChain == null? → kdfRk(rootKey, DH(свой_рatchet, ключ_Боба))  ← первый шаг цепочки
//     ChainStep step = kdfCk(sendChain)                                  ← ключ сообщения [§3.2]
//     свежая ротация? → прицепить свой ratchetPub (65 байт)
String e2ePayload = SessionCrypto.encrypt(text, ticket.messageKey(),
        ownName, recipient, ticket.sequence(), ticket.chainIndex(),
        ticket.newRatchetPublicKey());                                  // AES-GCM + AAD [§3.4]
sendRaw(ClientMessage.message(recipient, nonce, e2ePayload));
session.commitSend(ticket);      // цепочка и счётчики двигаются ТОЛЬКО после отправки
ticket.destroyMessageKey();      // ключ сообщения затёрт
```

### Шаг 3. Приём (на стороне B)

```java
// ChatClientCore.handleDM()
SessionCrypto.Header header = SessionCrypto.parseHeader(msg.e2ePayload);
SessionContext.ReceivePlan plan = session.planReceive(header);
//   planReceive():
//     1) sequence строго == ожидаемому      ← replay/gap отсекается ДО работы
//     2) флаг новой рatchet-ключа? → kdfRk ×2: новая принимающая цепочка,
//        СВОЯ новая пара, новая отправляющая цепочка           (всё — в «план»)
//     3) chainIndex == ожидаемому
//     4) messageKey = kdfCk(принимающая цепочка)                 ← ключ этого сообщения
String plainText = SessionCrypto.decrypt(payload, plan.messageKey(),
        from, ownName, header.sequence(), header.chainIndex());  // GCM-тег решает всё
session.commitReceive(plan);   // ← только ТЕПЕРЬ состояние меняется
plan.destroyMessageKey();
```

**Если тег не сошёлся** (подделка/чужой ключ) — исключение → `plan`
выброшен → ратчет **не сдвинулся**. Атакующий не может нам ничего подсунуть.

### Шаг 4. Следующий ход → ротация

```
B получил сообщение с новым ключом A₁  →  planReceive() делает kdfRk (шаг2)
B шлёт следующее сообщение с флагом + своим свежим ключом B₂
A получил B₂  →  kdfRk (шаг2)  →  корень у обоих снова равен
```

Правило: **ротируюсь только когда получил свежий ключ от собеседника** —
поэтому последовательность KDF-шагов у обеих сторон одинаковая, цепочки
сходятся (это проверяет `RatchetTest.multiTurnConversationConvergesWithRotationPerTurn`).

---

## §6. Связь с «пунктами безопасности»

| Пункт из SECURITY.md | Реализовано вот этим |
|----------------------|----------------------|
| **№1 — сервер раздаёт ключи** | `KeyFingerprint.hex()` (отпечаток), `PeerTrustStore` (TOFU-файл + блокировка), `SafetyNumber` (сверка двух ключей), команды `/fingerprint`, `/safety`, `/trust` в `ConsoleTui` |
| **№2 — нет per-message forward secrecy** | `SessionCrypto.kdfCk` (ключ на сообщение) + `kdfRk` (DH-ротация), двухфазные `beginSend/planReceive` в `SessionContext` |
| Транспорт | TLS 1.3 фабрики (§3.10) |
| Аутентификация входа | BCrypt + JWT (§3.8–3.9) |
| Защита ключей на диске | PBKDF2 + GCM (§3.7) |

---

## §7. Правила запоминания (если забыл всё — чти это)

1. **SHA-256 / HMAC — односторонние.** Назад нельзя. Поэтому цепочка ключей
   течёт только вперёд → прошлое защищено.
2. **ECDH даёт секрет, но не аутентифицирует.** Кто подделал публичный
   ключ — тот и «Боб». Отсюда RSA-подписи (§3.6) и TOFU (§6).
3. **HKDF — только производная.** Из сырого ECDH-секрета делаем root,
   confirm и т.д. Сырой секрет никогда не шифрует.
4. **AES-GCM = шифрование + тег.** AAD — то, что нельзя тихо поменять.
5. **Подпись покрывает контекст** (роль, имена, ключ) — иначе её можно
   переиграть в другой роли.
6. **Ключ живёт ровно столько, сколько нужно:** messageKey — одно сообщение,
   цепочка — до ротации, rootKey — сессия, RSA — «всегда», пароль — никогда
   не хранится (только хеш).
7. **Валидируй вход, доверяй выходу:** точка на кривой? версия кадра?
   username из JWT, а не из полей? — всё проверяется до использования.
8. **Двухфазность = устойчивость:** посчитал → проверил → применил.
   Не применил ничего, пока тег не сошёлся.
9. **Fail-closed:** нет секрета/сертификата — не стартуем; расхождение
   ключа — не шлём; битый файл — не читаем.
10. **Метаданные видит сервер всегда.** E2E прячет только тело сообщения.

**Забыл, где что? Ищи по симптому:**

| Симптом/вопрос | Файл |
|----------------|------|
| «Откуда берутся ключи сообщений?» | `crypto/SessionCrypto.java` (`kdfCk`, `kdfRk`) |
| «Что происходит при handshake?» | `client/ChatClientCore.java` (`handleInitSessionAsync`, `handleSessionAck`) |
| «Где состояние сессии и ратчета?» | `client/SessionContext.java` |
| «Как ловят подмену ключа?» | `client/PeerTrustStore.java`, `crypto/KeyFingerprint.java` |
| «Как шифруется кадр?» | `crypto/SessionCrypto.java` (`encrypt`, `parseHeader`, `decrypt`) |
| «Как хранится приватный ключ?» | `crypto/keyStorage/FileBasedKeyStorage.java`, `crypto/PbeUtil.java` |
| «Как проверяется пароль/токен?» | `auth/LocalAuthProvider.java`, `auth/JwtService.java` |
| «Как настроен TLS?» | `client/TlsClientContextFactory.java`, `server/TlsServerContextFactory.java` |
| «Какие есть тесты-наглядки?» | `RatchetTest` (сходимость), `SessionContextTest`, `PeerTrustStoreTest` |

---

## §8. Глоссарий

| Термин | Значение |
|--------|----------|
| **IV / nonce** | Случайные12 байт на сообщение — чтобы один ключ не шифровал два раза одинаково |
| **AAD** | Данные, не шифруемые сами, но включённые в GCM-тег (нельзя подделать) |
| **Тег (tag)** |16 байт в конце шифртекста — «сургуч», доказывающий целостность |
| **Соль (salt)** | Случайные байты, уникальные на каждый объект (файл, пароль) |
| **IKM / PRK** | В HKDF: входной материал / промежуточный ключ после extract |
| **root key** | Общий корень ратчета, общий у обеих сторон |
| **chain key** | Текущая цепочка, из которой растёт ключ сообщения |
| **message key** | Ключ одного конкретного сообщения (AES-256) |
| **рatchet** | «Храповик»: шаг только вперёд, назад нельзя |
| **forward secrecy** | Утечка текущего ключа не открывает прошлые сообщения |
| **break-in recovery** | После утечки новые сообщения снова закрыты (DH-ротация) |
| **TOFU** | Trust On First Use — первый ключ доверяем «на слово», дальше фиксируем |
| **safety number** |60-значное число из двух ключей для сверки вне канала сервера |
| **транскрипт** | Хеш всех параметров handshake — привязка ключей к переговорам |
| **key confirmation** | Обмен тегами, доказывающий, что обе стороны вывели одинаковые ключи |
| **identity-ключ** | Долгоживущая RSA-пара пользователя (подписи handshake) |
| **эфемерный ключ** | Одноразовая P-256-пара, живёт один handshake |

---

## §9. Практика: запустить и поиграться

```powershell
# все крипто-тесты (14 наборов, включая RatchetTest)
$env:JAVA_HOME="C:\path\to\jdk-23+"
.\gradlew.bat test --tests org.ugina.SessionCryptoTest --tests org.ugina.SessionContextTest `
  --tests org.ugina.RatchetTest --tests org.ugina.EcdhCryptoTest --tests org.ugina.HkdfCryptoTest
```

Что посмотреть руками, чтобы «примерить» гайд:

1. **Цепочка ключей:** `RatchetTest.everyMessageGetsItsOwnKey` — печатает
   (в отладке)10 разных ключей для10 сообщений.
2. **Ротация:** `RatchetTest.multiTurnConversationConvergesWithRotationPerTurn` —
   флаг «новый ключ» только на первом сообщении каждого хода.
3. **Отказ при подделке:** `SessionContextTest.forgedMessageCannotCorruptRatchetState` —
   бит в ciphertext → состояние не изменилось.
4. **TOFU:** `PeerTrustStoreTest.changedKeyIsRejectedAndKeptAsPending` —
   подмена ключа → отказ + `/trust`.

Порядок изучения кода: `ChatClient.sendMessage` → `SessionContext.beginSend`
→ `SessionCrypto.encrypt` → (сеть) → `SessionCrypto.parseHeader` →
`SessionContext.planReceive` → `SessionCrypto.decrypt` → `commitReceive`.
Эти семь вызовов — весь путь сообщения.
