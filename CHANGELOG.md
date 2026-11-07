# Changelog

## 2026-11-05 — Security hardening v0.6

Ниже сохранён полный отчёт об анализе и первичной доработке проекта.
Этот документ можно читать как учебный конспект: в нём объясняется, что
было не так, как теперь устроено шифрование и какие риски остались.

---

# Secure-Socket-Chat: анализ и доработка безопасности

## Краткий вывод

До правок проект **нельзя было считать безопасным**:

- в git лежал статический AES-PSK, которым шифровался весь прикладной протокол;
- JWT-секрет по умолчанию был публичным placeholder’ом;
- TLS разрешал 1.2;
- E2E-схема не давала аутентификации отправителя и защиты от replay;
- handshake не был привязан к ролям и именам;
- username напрямую попадал в путь файла ключа;
- `ddl-auto` был `create-drop`.

Сейчас транспорт защищён **только TLS 1.3**, PSK удалён, а E2E работает по протоколу v2: **P-256 ECDH + HKDF с привязкой к транскрипту + RSA-подпись handshake + раздельные AES-256-GCM ключи направлений + sequence numbers в AAD + явное подтверждение ключа**.

Это уже нормальный уровень для учебного/демонстрационного проекта. Для production всё ещё не хватает key transparency/safety numbers, ratchet’а и независимого аудита — подробности ниже.

---

## 1. Как было устроено шифрование до правок

### Транспорт

TLS был, но:

- разрешались `TLSv1.2,TLSv1.3`;
- клиент не проверял hostname;
- сертификаты и пароли были фактически dev-значениями;
- TLS был единственным реальным барьером, потому что прикладной слой использовал закоммиченный ключ.

### Прикладной слой: статический PSK

`KeyLoader` читал `chat.aes.key` из `application.properties`:

```properties
chat.aes.key=Y3jK8mB2pF9wQ4xN7vR1aH5tL6sD0eU3oC2iZ4bV8nM=
```

`ClientCipherService` шифровал этим ключом **каждый** кадр протокола. Ключ был в репозитории, общий для всех клиентов и сервера. То есть:

- любой, у кого есть исходники, знал «секретный» ключ;
- сервер мог расшифровать весь прикладной протокол;
- при ошибке конфигурации TLS защита исчезала полностью;
- сменить ключ без пересборки было нельзя.

### E2E-шифрование сообщений

`HybridCrypto` на каждое сообщение:

1. генерировал случайный AES-256 ключ;
2. шифровал им текст;
3. шифровал AES-ключ RSA-OAEP публичным ключом получателя.

Проблемы:

- **нет forward secrecy** — всё завязано на долговременный RSA-ключ;
- **нет аутентификации отправителя** — любой, кто знает публичный ключ получателя, мог сформировать сообщение;
- **нет привязки к отправителю, получателю и сессии**;
- nonce не входил в AAD и не защищался GCM;
- replay и переупорядочивание не обнаруживались.

### Handshake

Был ECDH P-256 + HKDF, но:

- HKDF использовал `salt = null` и одинаковый `info`;
- RSA-подпись покрывала только эфемерный публичный ключ;
- не подписывались роль, имя отправителя и имя получателя;
- отсутствовало явное подтверждение ключа.

Из-за этого возможны cross-peer replay и identity misbinding: captured `INIT_SESSION` можно было попытаться переиграть в другом контексте.

### Аутентификация и политики

- JWT-секрет по умолчанию: `change-me-in-production-this-must-be-at-least-256-bits-long`.
- Spring Security auto-configuration исключалась, то есть REST-эндпоинты фактически были открыты.
- `SecurityConfig` не задавал deny-by-default.
- `ddl-auto: create-drop` — схема БД пересоздавалась при старте.
- `KeyManager` строил путь как `~/.secure-chat/<username>.key` без валидации username → path traversal.
- Не было ограничений на размер кадров, очередей, карт, число команд.
- Ошибки могли уходить клиенту со stack trace.
- PBKDF2 использовал 100 000 итераций.
- Ключевые массивы и пароли не затирались.

---

## 2. Как шифрование работает сейчас

### Транспорт

- REST: `https://localhost:8443`, только `TLSv1.3`.
- Чат: TCP-порт `5000`, `SSLServerSocket` только с `TLSv1.3`.
- Клиент проверяет hostname (`endpointIdentificationAlgorithm=HTTPS`) и использует отдельный truststore, а не JVM default.
- Dev-сертификаты генерируются локально скриптом `certs/generate-dev-certs.ps1` и не коммитятся.
- При отсутствии keystore/пароля приложение падает с явной ошибкой, а не стартует без TLS.

### Аутентификация

1. `POST /api/auth/register`: username, BCrypt-пароль, RSA-публичный ключ.
2. Публичный ключ проверяется: RSA ≥ 2048 бит, exponent ≥ 65537.
3. `POST /api/auth/login`: BCrypt-проверка, затем JWT HS256 с issuer `secure-chat`.
4. JWT проверяется по подписи, issuer, сроку и subject.
5. При `JOIN` сервер берёт username **из JWT**, а не из клиентского поля.
6. Пароль и публичный ключ нельзя подменить после регистрации.

### E2E handshake v2

Инициатор A → получатель B:

1. A получает RSA-ключ B через сервер (`GET_KEY`).
2. A генерирует эфемерную пару P-256.
3. A подписывает своим RSA-ключом канонический payload:

```text
"secure-chat/v2/handshake" || role="init" || A || B || ephemeralPub_A
```

4. B проверяет подпись, генерирует свою эфемерную пару, считает ECDH.
5. B подписывает:

```text
"secure-chat/v2/handshake" || role="ack" || B || A || ephemeralPub_B
```

6. Обе стороны считают:

```text
transcriptHash = SHA-256(label || A || B || ephemeralPub_A || ephemeralPub_B)
```

7. HKDF-SHA256 с `salt = transcriptHash` выводит четыре независимых значения:
   - `i2r` — ключ A → B;
   - `r2i` — ключ B → A;
   - `initiator-confirm`;
   - `responder-confirm`.
8. B отправляет `SESSION_ACK` с эфемерным ключом, подписью и своим confirmation.
9. A проверяет подпись и confirmation в constant-time, отправляет `SESSION_CONFIRM`.
10. Только после проверки `SESSION_CONFIRM` B переводит сессию в `READY`.

Ключевые свойства:

- подпись привязана к роли и обоим именам;
- ключи привязаны к полному транскрипту;
- направления разделены;
- обе стороны явно подтверждают, что вывели одинаковые ключи.

### Сообщения

Формат E2E-payload:

```text
[version:1 = 0x02][sequence:8][IV:12][AES-GCM ciphertext + tag]
```

AAD:

```text
version || lengthPrefixed(sender) || lengthPrefixed(recipient) || sequence
```

Свойства:

- AES-256-GCM;
- случайный 96-битный IV на сообщение;
- строгий sequence: принимается только `lastReceived + 1`;
- replay, переупорядочивание и пропуски отклоняются;
- разные ключи для разных направлений;
- сервер видит только `from`, `to`, размер и ciphertext, но не plaintext.

### Хранение ключей

- Приватный RSA-ключ шифруется `PBKDF2-HMAC-SHA256` (600 000 итераций) + `AES-256-GCM`.
- Новый формат файла версионирован (`SCK1`), старые файлы ещё читаются.
- Запись атомарная: temp-файл + rename.
- На POSIX-файловых системах выставляются права `0600`.
- Ключи и confirmation-теги оборачиваются в `DestroyableSecretKey` и затираются при завершении/ошибке/истечении сессии.
- Пароль читается через `readPassword()` и затирается после использования.

### Политики

- `SecurityConfig`: публичны только `POST /api/auth/register` и `POST /api/auth/login`, всё остальное — `denyAll`.
- `JWT_SECRET` отсутствует/короткий/публичный → генерируется случайный per-process секрет и пишется warning.
- `ddl-auto: validate`, схемой владеет Flyway.
- SQL-логирование выключено.
- Ошибки без stack trace и текста исключения.
- Ограничены размеры кадров, пулы потоков, карты, число команд на соединение.
- Username: только `[A-Za-z0-9_]{1,32}` — path traversal закрыт.
- Rate limit на register/login и на команды чата.

---

## 3. Оценка: что стало лучше

| Свойство | Было | Стало |
|---|---|---|
| Транспорт | TLS 1.2/1.3 | только TLS 1.3 |
| Статический PSK в git | да | удалён |
| Конфиденциальность от сервера | зависела от PSK/сервера | E2E AES-256-GCM |
| Forward secrecy | нет | сессионная, но без ratchet |
| Аутентификация отправителя | нет | RSA-подпись handshake + session keys |
| Привязка к ролям/именам | нет | да, в подписи и транскрипте |
| Key confirmation | нет | явный `SESSION_CONFIRM` |
| Replay/переупорядочивание | не обнаруживались | sequence + AAD |
| JWT | публичный дефолт | fail-safe secret + issuer |
| REST-политика | фактически открыто | deny-by-default |
| Path traversal | да | закрыт `UsernamePolicy` |
| Ограничения ресурсов | почти нет | кадры, пулы, карты, rate limit |
| Секреты в репозитории | PSK + JWT placeholder | `.env` и сертификаты gitignored |

---

## 4. Что именно изменено в коде

Основные файлы:

- `app/src/main/java/org/ugina/crypto/SessionCrypto.java` — ядро E2E v2.
- `app/src/main/java/org/ugina/crypto/DestroyableSecretKey.java` — затираемые ключи.
- `app/src/main/java/org/ugina/client/SessionContext.java` — state machine сессии, sequence numbers, подтверждения.
- `app/src/main/java/org/ugina/client/ChatClientCore.java` — handshake, сессии, маршрутизация, подтверждение.
- `app/src/main/java/org/ugina/server/ChatHandler.java` — TLS-соединение, JOIN, валидация.
- `app/src/main/java/org/ugina/server/ChatRoom.java` — маршрутизация, replay-кэш.
- `app/src/main/java/org/ugina/server/ServerHandlerService.java` — проверки сообщений и handshake.
- `app/src/main/java/org/ugina/server/ChatServer.java` — bounded TLS 1.3 listener.
- `app/src/main/java/org/ugina/auth/JwtService.java` — fail-safe secret, issuer.
- `app/src/main/java/org/ugina/auth/LocalAuthProvider.java` — timing-safe login, регистрация.
- `app/src/main/java/org/ugina/config/SecurityConfig.java` — deny-by-default.
- `app/src/main/java/org/ugina/ratelimit/RateLimitService.java` — ограничения.
- `app/src/main/java/org/ugina/utils/UsernamePolicy.java` — единая политика имён.
- `app/src/main/java/org/ugina/crypto/PbeUtil.java` — PBKDF2 v2 с версионированием.
- `app/src/main/java/org/ugina/crypto/keyStorage/FileBasedKeyStorage.java` — атомарная запись и права.
- `app/src/main/java/org/ugina/crypto/AesCrypto.java`, `EcdhCrypto.java`, `RsaCrypto.java`, `RsaSignature.java` — ужесточённые примитивы.
- `app/src/main/java/org/ugina/client/TlsClientContextFactory.java`, `server/TlsServerContextFactory.java` — TLS.
- `app/src/main/resources/application.yml` — TLS 1.3, `validate`, лимиты.
- `app/src/main/resources/logback.xml` — ротация логов без потери данных.
- `app/build.gradle` — корректная загрузка `.env`, `workingDir`.
- `.env.example`, `.gitignore` — секреты и сертификаты не попадают в git.
- `SECURITY.md` — модель угроз и остаточные риски.
- `protocol/RU/PROTOCOL_06.md`, `protocol/EN/PROTOCOL_06.md` — спецификация v2.
- `README.md`, `README_RU.md` — актуализированы.
- Удалён мёртвый PSK-код, включая `KeyGenUtil`.

---

## 5. Проверка

Выполнено:

- **10 тестовых наборов, 50 тестов — 0 падений.**
- Полный Spring Boot запуск на временном PostgreSQL:
  - Flyway применил миграции;
  - приложение слушало `8443` и `5000`.
- E2E smoke-тест:
  - регистрация двух пользователей;
  - логин;
  - `JOIN`;
  - E2E handshake;
  - отправка сообщения;
  - получение plaintext;
  - `DELIVERED`.
  - Результат: `E2E_SMOKE_OK`.
- TLS-проверка:
  - `8443` → `TLSv1.3`, `TLS_AES_256_GCM_SHA384`;
  - `5000` → `TLSv1.3`, `TLS_AES_256_GCM_SHA384`;
  - TLS 1.2 на обоих портах отклоняется с `protocol_version`.
- Проверено, что `.env`, `*.p12`, `*.crt`, `21062007*` не отслеживаются git.
- Временный PostgreSQL и `bootRun` остановлены, `.env` возвращён на порт `5432`.

---

## 6. Остаточные риски

Это важно понимать: проект стал заметно безопаснее, но **не является production-ready**.

1. **Сервер доверенно раздаёт публичные ключи.** Злонамеренный сервер может подменить ключ B и организовать MITM. Нужны safety numbers, key transparency или pinning.
2. **Нет per-message forward secrecy.** Ключи живут до 30 минут idle / 24 часов absolute. Нужен Double Ratchet.
3. **Нет отзыва и ротации ключей.** Публичный ключ привязан к username навсегда; JWT живёт до истечения, серверного revocation list нет.
4. **Нет проверки владения username при регистрации.** Возможен username squatting; нет email/иного подтверждения.
5. **Метаданные видны серверу:** кто, с кем, когда, сколько байт.
6. **Rate limiting in-memory.** За reverse proxy все клиенты могут делить один bucket; несколько инстансов не разделяют состояние.
7. **Windows ACL.** POSIX `0600` на Windows не применяется; нужен BitLocker/EFS и защищённый профиль.
8. **JVM может копировать ключевые массивы.** Затирание best-effort.
9. **Legacy PBE v1 остаётся для чтения старых файлов.** Новые файлы всегда v2.
10. **Нет независимого аудита.** Криптография реализована вручную; для реальных чувствительных данных нужен аудит и, желательно, проверенные библиотеки.
11. **Dev-сертификаты self-signed.** Для production нужен реальный CA и защищённое хранение ключа.
12. **Полный Spring test suite не прогонялся** из-за локальной PostgreSQL-аутентификации; вместо него приложение проверено ручным запуском и E2E smoke-тестом.

---

## 7. Как запускать

```powershell
Copy-Item .env.example .env
powershell -ExecutionPolicy Bypass -File certs/generate-dev-certs.ps1

# Заполнить в .env:
#   DB_PASSWORD
#   JWT_SECRET (минимум 32 случайных байта)
#   TLS_KEYSTORE_PASSWORD / TLS_KEY_PASSWORD / TLS_TRUSTSTORE_PASSWORD

.\gradlew.bat bootRun
.\gradlew.bat runClient
```

Сгенерировать JWT-секрет:

```powershell
powershell -Command "[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))"
```

Проверить TLS:

```powershell
openssl s_client -connect localhost:8443 -tls1_3
openssl s_client -connect localhost:5000 -tls1_3
```

---

## 8. Статус изменений

Все правки **не закоммичены**. В рабочем дереве также есть служебные изменения `.idea/*` и `gradle/wrapper/gradle-wrapper.properties` — они не относятся к безопасности, их можно не включать в коммит.

Не добавляйте в git:

- `.env`;
- `certs/*.p12`, `certs/*.crt`;
- `21062007`, `21062007.pub`;
- логи и локальные keystore/truststore.

Коммитить имеет смысл исходники, тесты, `SECURITY.md`, `protocol/*`, `README*`, `.gitignore`, `.env.example`, `certs/README.md` и `certs/generate-dev-certs.ps1`.


---

## 2026-11-05 — Улучшение №1: проверка ключей (TOFU + safety number)

### Что было проблемой

E2E-шифрование защищает содержимое сообщений, но ему нужны **аутентичные
публичные ключи**. Их раздаёт сервер. Если сервер вредоносный или
скомпрометирован, он может вместо ключа Боба вернуть свой ключ:

1. Алиса запрашивает ключ Боба (`GET_KEY`).
2. Сервер отдаёт **свой** ключ, подделав имя Боба.
3. Алиса подписывает handshake этим ключом — сообщение попадает в зону,
   которую контролирует сервер.
4. Сервер расшифровывает его и перешифровывает Бобу.

TLS здесь не помогает: он заканчивается на сервере. RSA-подпись тоже не
помогает: `INIT_SESSION` будет подписан именно тем ключом, который выдал
сервер. Это не проблема криптографии, а проблема **распределения ключей**.

### Что сделано

Реализованы две взаимодополняющие защиты.

**1. TOFU-закрепление ключей (`PeerTrustStore`).**

- Файл `~/.secure-chat/known-peers.tsv` хранит соответствие
  `username → SHA-256 fingerprint`.
- При первом контакте ключ закрепляется автоматически (Trust On First Use).
- При последующих `GET_KEY` клиент сравнивает полученный ключ с закреплённым.
- Если сервер вернул **другой** ключ:
  - клиент отказывается его использовать;
  - показывает предупреждение с ожидаемым и полученным fingerprint;
  - хранит новый ключ только во внутренней «очереди ожидания», не в кэше;
  - handshake и отправка блокируются.
- Ключ принимается только вручную: `/trust <user> <fingerprint-prefix>`
  (минимум 16 hex-символов).
- Файл пишется атомарно (temp + rename), права `0600` на POSIX; при
  повреждении файла клиент падает с ошибкой, а не начинает историю заново.

**2. Safety number (`SafetyNumber`).**

- SHA-256 от домен-разделённой, длина-префиксной кодировки
  `(label, usernameA, keyA, usernameB, keyB)` в каноническом порядке
  (сортировка по именам, чтобы обе стороны получали одно значение).
- Результат — 60 цифр, разделённых на 12 групп по 5 цифр (как в Signal).
- Обе стороны считают одинаковое число независимо от того, кто начал разговор.
- Если сервер подменил ключ одной из сторон, числа **не совпадут**.

### Найден и исправлен баг (пойман E2E-тестом)

Пока шла проверка, выяснилось, что два клиента, открытых под одним
пользователем Windows (как и рекомендует README для двух окон чата),
пользовались **одним файлом закреплённых ключей**, но каждый писал его целиком
из своей памяти. В итоге:

1. клиент A закреплял ключ Боба и записывал его в файл;
2. клиент B (открыт чуть позже, с копией файла «на момент старта») закреплял
   Алису и **перезаписывал файл целиком**, стирая закрепление Боба;
3. потерянное закрепление молча возвращалось в режим TOFU — то есть защита
   от подмены ключа незаметно отключалась.

Исправление в `PeerTrustStore`:

- **межпроцессная блокировка** на отдельном файле `known-peers.tsv.lock`
  (через `FileChannel.lock()`), чтобы писатели не пересекались;
- **`refreshFromDisk()`** — перед записью файл перечитывается, и все записи,
  которые *не менял* текущий процесс, обновляются с диска;
- **трекинг «грязных» записей** (`dirty`) — решение, принятое текущим
  процессом (первое закрепление или `/trust`), никогда не откатывается
  более старым значением с диска.

### Как пользоваться

| Команда | Назначение |
|---------|-----------|
| `/fingerprint` | Показывает полный fingerprint вашего identity-ключа |
| `/safety <user>` | Показывает safety number и fingerprint ключа собеседника |
| `/trust <user> <fp>` | Принимает новый ключ после сверки по другому каналу |

При первом контакте клиент печатает fingerprint и предлагает выполнить
`/safety <user>` у обоих собеседников. Числа нужно сравнить по каналу, который
не контролирует сервер (лично, по телефону, в подписанном сообщении).

### Что это даёт и чего не даёт

| Сценарий | Защита |
|----------|--------|
| Сервер подменяет ключ **после** первого контакта | Да — блокировка до `/trust` |
| Сервер подменяет ключ **при первом** контакте | Только ручная сверка safety number |
| Злонамеренный клиент регистрирует имя Боба | Нет — username squatting, см. SECURITY.md §9 |
| Ключи не менялись | Работает как раньше, без действий |

**Важно:** TOFU не устраняет доверие к серверу при первом контакте полностью.
Полное решение — key transparency (append-only log ключей), это план на v0.7.

### Изменённые файлы

- `org.ugina.crypto.KeyFingerprint` — новый, fingerprint ключа.
- `org.ugina.crypto.SafetyNumber` — новый, safety number.
- `org.ugina.client.PeerTrustStore` — новый, TOFU-хранилище.
- `org.ugina.client.PeerKeyMismatchException` — новый, типизированная ошибка.
- `ChatClientCore` — проверка ключей, `ownFingerprint`, `peerFingerprint`,
  `safetyNumber`, `trustPendingPeerKey`.
- `ChatEventListener` — колбэки `onPeerKeyTrusted` / `onPeerKeyChanged`.
- `ConsoleTui` — команды `/fingerprint`, `/safety`, `/trust` и подсказки.
- `SECURITY.md`, `README.md`, `README_RU.md`, `protocol/*/PROTOCOL_06.md`.

### Проверки

- 13 тестовых наборов, **68 тестов, 0 падений** (добавлены
  `KeyFingerprintTest`, `SafetyNumberTest`, `PeerTrustStoreTest`, включая
  регрессионный тест на «устаревшую» копию файла закреплений).
- E2E smoke-тест (регистрация → логин → JOIN → handshake → сообщение →
  `DELIVERED`) — `E2E_SMOKE_OK`, прогнан дважды.
- E2E negative-тест `TRUST_BLOCK_RECOVERY_OK`: в файл закреплений подсунут
  **неверный** fingerprint, дальше проверено, что
  1) отправка блокируется `PeerKeyMismatchException` и срабатывает
     `onPeerKeyChanged` с правильными отпечатками;
  2) `/trust` с префиксом настоящего ключа разблокирует handshake;
  3) сообщение после этого доходит в открытом виде, файл закреплений
     обновлён на настоящий ключ.
- TLS по-прежнему `TLSv1.3` / `TLS_AES_256_GCM_SHA384` на `8443` и `5000`.
- После проверок сервер, временный PostgreSQL и `.env` (порт `5432`)
  возвращены в исходное состояние; `~/.secure-chat` не затрагивался
  (тесты шли с отдельным trust-файлом через `secure.chat.trustStore`).

---

## 2026-11-05 — Учебный гайд по криптографии

Создан [`CRYPTO_GUIDE_RU.md`](CRYPTO_GUIDE_RU.md) — гайд для новичка по всем
алгоритмам проекта:

- карта пути сообщения `@bob привет` (5 этапов: файл → метод → алгоритм);
- шпаргалка «роль каждого алгоритма» (SHA-256, HMAC, HKDF, AES-GCM, ECDH,
  RSA-подписи, PBKDF2, BCrypt, JWT, TLS 1.3);
- разбор каждого алгоритма с реальными фрагментами кода из репозитория;
- иерархия ключей и таблица «где что хранится и сколько живёт»;
- жизнь одного сообщения по шагам (handshake → шифрование → приём → ротация);
- правила запоминания, таблица «симптом → файл», глоссарий, практика.

Ссылки на гайд добавлены в `README_RU.md` и `README.md`.

---

## 2026-11-05 — Улучшение №2: пер-месседжный forward secrecy (E2E v3)

### Проблема

В v2 одно AES-ключ шифровал **всю сессию** (до30 минут простоя /24 часов
абсолютного возраста). Утечка этого ключа (дамп памяти, баг) открывала
**все** сообщения сессии, включая отправленные до утечки.

### Что сделано — протокол E2E v3

**1) Симметричный рatchet (защита прошлого):**

```
chain_n ──HMAC──► chain_{n+1} ──HMAC──► ...
   │
   └── HMAC(chain_n, "…/msg-key") ──► messageKey_n   ← ключ ОДНОГО сообщения
```

Односторонность HMAC: зная `messageKey_n` или `chain_{n+1}`, назад не
пройти — прошлые сообщения закрыты навсегда.

**2) DH-рatchet (защита будущего / break-in recovery):**

- при получении сообщения со **свежим** ratchet-ключом собеседника:
  `step1` — новая принимающая цепочка + `step2` — своя новая P-256-пара и
  новая отправляющая цепочка, корень пересчитывается через `KDF_RK`;
- ротация **только по получению** (не самостоятельно) — обе стороны
  применяют одинаковую последовательность KDF-шагов и сходятся на
  идентичных цепочках; одновременная ротация невозможна по построению.

**3) Формат кадра v3:**

```
[version:3][flags][ratchetPub?:65][sequence:8][chainIndex:8][IV:12][GCM]
```

- `flags` + ratchetPub — только в первом сообщении после ротации;
- `sequence` — глобальный счётчик (+1 строго);
- `chainIndex` — позиция в цепочке (сбрасывается при ротации);
- AAD = версия || флаг || ключ || имена || sequence || chainIndex —
  сервер не может ни подменить отправителя, ни выкинуть флаг ротации.

**4) Двухфазное обновление состояния:**

- `beginSend()` / `planReceive()` — всё считается в «тикет/план»;
- `commitSend()` / `commitReceive()` — состояние меняется только после
  записи в сеть / проверки GCM-тега;
- подделанный кадр → тег не сошёлся → план выброшен → рatchet не сдвинулся.

### Изменённые файлы

- `SessionCrypto` — v3: `kdfRk` (DHKDF), `kdfCk` (цепочка), `derive` →
  `rootKey` + confirm-теги, формат кадра, `parseHeader`, новый AAD.
- `SessionContext` — состояние ратчета (корень, цепочки, DH-пара, индексы),
  `beginSend/commitSend`, `planReceive/commitReceive`, затирание материала.
- `EcdhCrypto` — `publicKeyToRaw` / `publicKeyFromRaw` (65 байт) + проверка
  точки на кривой P-256 (точка вне кривой не доходит до `KeyAgreement`).
- `ChatClientCore` — отправка через тикет, приём через план.
- Тесты: `SessionCryptoTest` и `SessionContextTest` переписаны под v3,
  добавлен `RatchetTest`.
- Документы: `SECURITY.md` (§2–§4, §7, §9), `README.md`, `README_RU.md`,
  `ConsoleTui` → v0.7.

### Проверки

- **14 тестовых наборов,84 теста,0 падений.**
- `RatchetTest` (сходимость вживую, два SessionContext без сети):
  -4 хода ×3 сообщения: ротация в каждом ходе, всё расшифровывается;
  - флаг нового ключа только на первом сообщении хода;
  -10 сообщений →10 уникальных ключей (пер-месседжный FS);
  - ключ сообщения №1 не открывает №2; корень меняется на каждой ротации;
  - кадр чужой сессии / подделанный кадр / gap — отклонены, состояние не
    тронуто, последующий легитимный кадр проходит.
- **E2E по сети** (сервер + временный PostgreSQL): `E2E_SMOKE_OK` —
  регистрация → логин → JOIN → handshake v3 → сообщение → `DELIVERED`.
- **E2E negative**: `TRUST_BLOCK_RECOVERY_OK` — подмена ключа блокируется,
  `/trust` разблокирует, сообщение доходит (работает и на v3).
- TLS `TLSv1.3` / `TLS_AES_256_GCM_SHA384` на `8443` и `5000`.
- После проверок сервер, PostgreSQL и `.env` остановлены/возвращены
  (`5432`); `~/.secure-chat` не затрагивался.

### Остаток по пункту

- ~~`protocol/RU/PROTOCOL_07.md` и `protocol/EN/PROTOCOL_07.md`~~ —
  **закрыто**: спецификация v3 выложена (см. следующий раздел).

---

## 2026-11-05 — Документационный долг: спецификация протокола v3

Созданы [`protocol/RU/PROTOCOL_07.md`](protocol/RU/PROTOCOL_07.md) и
[`protocol/EN/PROTOCOL_07.md`](protocol/EN/PROTOCOL_07.md) — полная
спецификация протокола E2E v3 (релиз v0.7):

- таблица изменений v2 → v3;
- handshake v3: label `secure-chat/v3/handshake`, вывод `root` + confirm,
  начальные цепочки ратчета (ленивая у инициатора, шаг 1+2 у ответчика);
- формат кадра `[ver][flags][ratchetPub?][seq][chainIdx][IV][CT]`, AAD,
  правила приёма (7 пунктов);
- kdfCk/kdfRk, правила сходимости ратчета (только receive-triggered,
  направление `dir`, флаг на первом сообщении каждого направления);
- двухфазность (`beginSend/commitSend`, `planReceive/commitReceive`);
- требование строгого порядка доставки и его последствия;
- обновлённые свойства безопасности и константы (версия `3`, флаг `0x01`,
  ratchet-ключ 65 байт, минимальный кадр 46/111 байт).

Сопутствующее:

- `PROTOCOL_06.md` (RU/EN) помечены как устаревшие, сохранены для истории;
- ссылки в `README.md` и `README_RU.md` переведены на `PROTOCOL_07`.

---

## 2026-11-05 — Улучшение №3 (часть A): refresh-токены и отзыв токенов

### Проблема

Украденный JWT жил до истечения (60 минут), «logout» был только на клиенте,
серверного отзыва не существовало, публичный ключ прибит к username
(часть B — ротация ключа — отложена).

### Что сделано

**Схема «короткий access + одноразовый refresh с ротацией»:**

1. **Access JWT —10 минут** (`JWT_EXPIRATION_MINUTES`, был60) + claims:
   - `jti` (UUID) — каждый токен уникален даже в пределах секунды;
   - `ver` = `users.token_version` — «поколение» токена.
2. **Refresh token** —32 случайных байта, в БД **только HMAC-SHA256**
   (keyed JWT-секретом), срок30 дней (`REFRESH_TOKEN_DAYS`), семья логина
   (`family_id`), поля `rotated_at`/`revoked_at`.
3. **Ротация**: `POST /api/auth/refresh` сжигает старый токен и выдаёт новый
   в той же семье.
4. **Reuse detection**: повторное предъявление сгоревшего/отозванного
   токена = кража → **вся семья отзывается**.
5. **Отзыв**: `POST /api/auth/logout` → семья отозвана + `token_version += 1`
   → **все** access-токены пользователя мертвы мгновенно (включая `JOIN`).
   Идемпотентно, без оракула валидности.
6. Проверка `ver` в `LocalAuthProvider.validate()` (покрывает REST и чат).
7. Rate limit: refresh/logout —30/час на IP (общий bucket).
8. Клиент: `AuthClient` хранит пару, авто-refresh за30 секунд до истечения,
   `logout()`; в чате команда `/logout`.

**Миграция** `V3__token_revocation.sql`: пересоздание `refresh_tokens`
(старая V2-таблица хранила токены открытым текстом и не использовалась
кодом) + `users.token_version`.

### Изменённые/новые файлы

- 🆕 `auth/RefreshTokenService.java`, `entity/RefreshToken.java`,
  `repository/RefreshTokenRepository.java`, `Dto/RefreshRequest.java`,
  `Dto/LogoutRequest.java`, `V3__token_revocation.sql`, `AUTH_GUIDE_RU.md`
- ✏️ `JwtService` (claims, `validate`→`Validated`, `hashRefreshToken`),
  `LocalAuthProvider` (пара токенов + проверка `ver`), `AuthToken`,
  `LoginResponse`, `AuthController` (`/refresh`, `/logout`), `SecurityConfig`,
  `RateLimitProperties`/`RateLimitService`, `application.yml`, `.env*`,
  `AuthClient`, `ConsoleTui` (`/logout`), `User` (+`tokenVersion`)

### Найдено и исправлено по ходу

- **Одинаковые access-токены в пределах секунды**: claims посекундные →
  два токена, выданные в одну секунду, были байт-в-байт идентичны.
  Лечение: claim `jti` (UUID) + регрессионный тест
  `everyTokenIsUniqueEvenWithinTheSameSecond`.

### Проверки

- **17 тестовых наборов,104 теста,0 падений** (добавлены `JwtServiceTest` —8,
  `RefreshTokenServiceTest` —7, `LocalAuthProviderTest` —6).
- **E2E по сети** `AUTH_FLOW_OK`: login → пара; refresh → новая пара;
  повтор старого refresh →401; sibling после reuse →401 (семья отозвана);
  JOIN с живым токеном → ок; logout → JOIN с тем же access →
  `INVALID_TOKEN`; новый вход/refresh после logout → работает.
- Регрессия: `E2E_SMOKE_OK` (чат v3 не сломан), Flyway V3 применён,
  Hibernate `validate` проходит.
- После проверок сервер/PostgreSQL остановлены, `.env` → `5432`.

### Остаток по пункту3

- **Часть B — ротация identity-ключа** (`/rotate-key` с повторной
  аутентификацией паролем + предупреждение пиров «ключ сменился» → `/trust`) —
  следующий шаг.
- Далее по плану: key transparency (закрытие пункта №1 полностью).

---

## 2026-11-05 — Улучшение №3 (часть B): ротация identity-ключа

### Проблема

Публичный RSA-ключ был прибит к username **навсегда**: утёк приватный
файл/устройство — способа заменить ключ не существовало. Это вторая половина
исходного пункта3 («нет ротации ключей»).

### Что сделано

**`POST /api/auth/rotate-key` + команда `/rotate-key` в чате.**

Три правила:

1. **Приватный ключ не покидает устройство** — пара генерируется на клиенте,
   сервер получает только публичную половину.
2. **Step-up аутентификация** — требуются И живой access-токен
   (`Authorization: Bearer`, проверяется подпись/срок/`ver`), И пароль.
   Украденный десятиминутный токен сам по себе ключ не подменит. Rate-limit
   `/rotate-key` делит bucket с `/login` («login:»+ip, 10/час) — единый
   бюджет на подбор пароля.
3. **Откат при ошибке** — локальный файл ключа заменяется первым; если сервер
   отказал, старый ключ восстанавливается: устройство и каталог ключей
   никогда не расходятся.

Поведение пиров (уже готовая механика из пункта1):

- следующий `GET_KEY` возвращает новый ключ → TOFU-проверка → предупреждение
  «ключ изменился» → блокировка до `/trust`;
- **самопочинка верификации** (`ChatClientCore.verifyPeerSignature`): пир с
  закешированным старым ключом на живом соединении получал бы `BAD_SIGNATURE`;
  теперь при несовпадении ключ сбрасывается, запрашивается заново (проходя
  через `PeerTrustStore`) и подпись проверяется повторно — пользователь видит
  явный флоу `/trust`, а не голую ошибку. Ложная подпись после повтора
  всё равно отклоняется.

### Изменённые/новые файлы

- 🆕 `Dto/RotateKeyRequest.java`
- ✏️ `AuthProvider` (+`rotateKey`), `LocalAuthProvider` (реализация:
  BCrypt-перепроверка + валидация ключа ≥2048 + UPDATE), `AuthController`
  (`/rotate-key`, парсер Bearer), `SecurityConfig` (6-й открытый путь),
  `KeyManager` (+`store` для замены/отката файла ключа), `AuthClient`
  (+`rotateKey`), `ConsoleTui` (`/rotate-key`, поле `loggedInUsername`,
  `handleInput` получил `stdin`), `ChatClientCore`
  (`verifyPeerSignature` + `refreshPeerKey`, два call-site handshake).

### Найдено по ходу

- `/rotate-key` без записи в `SecurityConfig` → **403** (denyAll) — поймано
  E2E-негативом «missing bearer must be401»; добавлен в `permitAll`.
- В харнессе `DELIVERED` ждался у получателя вместо отправителя (сервер
  шлёт его отправителю) — починено в тесте, не в продукте.

### Проверки

- **18 тестовых наборов,114 тестов,0 падений** (добавлены `rotateKey*` ×5 в
  `LocalAuthProviderTest`, новый `SignatureVerifyTest` ×4).
- **E2E по сети** `KEY_ROTATE_E2E_OK`:
  1) закреплённый старый ключ пира →2) негативы: без Bearer/мусорный
  Bearer/неверный пароль → **401**;3) ротация A1→A2 → **200**;
  4) отправка пиров **блокируется** с `onPeerKeyChanged` (в предупреждении
  настоящие отпечатки A1/A2);5) `/trust` → повтор → сообщение доставлено,
  `DELIVERED`, ключ пира = A2.
- Регрессия: `E2E_SMOKE_OK`.
- После проверок сервер/PostgreSQL остановлены, `.env` → `5432`.

### Документация

- `AUTH_GUIDE_RU.md` — новый §11 «Ротация identity-ключа» (флоу-диаграмма,
  код, самопочинка, ограничения, практика);
- `PROTOCOL_07` RU/EN — §3 дополнен `/rotate-key`;
- `SECURITY.md` — §6.1 (команда в таблице + абзац про ротацию);
- `README*` — roadmap v0.7: ротация отмечена готовой.

### Итог по пункту3 (часть A + B)

Пункт3 исходного списка **закрыт**: access10 мин + refresh с ротацией и
reuse detection, мгновенный отзыв через `token_version`, ротация
identity-ключа с step-up и откатом. Осталось из «маленького» в §9: смена
пароля, per-device logout, чистка просроченных refresh-строк.

Следующий большой пункт — **key transparency** (полное закрытие пункта1).
