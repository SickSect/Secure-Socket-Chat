# Гайд по аутентификации Secure Chat — токены, ротация, отзыв

> **Для новичка.** Как в этом проекте устроены вход, долгие сессии и
> **отзыв** токенов. Все примеры — реальные фрагменты кода репозитория.
> Читать по порядку: §1–§2 дают картину, §3–§6 — детали с кодом,
> §7–§9 — запоминание и практика.
>
> Дополняет [`CRYPTO_GUIDE_RU.md`](CRYPTO_GUIDE_RU.md) (там про сами
> алгорифмы: HMAC, JWT-подпись, BCrypt).

---

## §1. Зачем всё это нужно — одна история

**До правок:** логин выдаёт JWT на60 минут. Укради его (лог, дамп памяти,
malware) — и **60 минут полного доступа**, отозвать нельзя. «Выход» был
только на клиенте: сервер вообще не знал, что ты вышел.

**Аналогия:** пропуск, который нельзя отозвать. Пока срок не истёк — ходи.

**Теперь:** вход даёт **пару токенов**:

```
┌─────────────┐   логин    ┌──────────────────────────────┐
│   пароль    │ ─────────► │ access JWT  (10 минут)       │ ← «на витрине»,
└─────────────┘            │ refresh token (30 дней,      │    быстро умирает
                           │  одноразовый, отзываемый)    │ ← «в сейфе»,
                           └──────────────────────────────┘    живёт долго
```

- **Access** нужен часто и живёт мало: если утек — устареет быстро.
- **Refresh** нужен редко (чтобы получить новый access) и живёт долго:
  поэтому его **храним в БД хешем**, он **одноразовый** и его можно
  **отозвать**.

---

## §2. Карта: где что живёт

| Этап | Файл | Метод |
|------|------|-------|
| Вход: пароль → пара токенов | `auth/LocalAuthProvider.java` | `authenticate()` |
| Выпуск JWT (claims `jti`, `ver`, `exp`) | `auth/JwtService.java` | `generate()` |
| Выпуск/ротация/отзыв refresh | `auth/RefreshTokenService.java` | `issue()`, `rotate()`, `revoke()` |
| REST-эндпоинты | `controller/AuthController.java` | `POST /login`, `/refresh`, `/logout` |
| Что вообще открыто | `config/SecurityConfig.java` | `permitAll(...)` (ровно4 пути) |
| Проверка токена (включая JOIN в чат) | `auth/LocalAuthProvider.java` | `validate()` |
| Схема БД | `db/migration/V3__token_revocation.sql` | `refresh_tokens`, `users.token_version` |
| Клиент: хранение и авто-refresh | `client/AuthClient.java` | `getValidAccessToken()`, `refreshTokens()`, `logout()` |
| Выход в чате | `client/ConsoleTui.java` | команда `/logout` |
| Rate limits | `config/RateLimitProperties.java` + `ratelimit/RateLimitService.java` | register 5/ч, login 10/ч, refresh 30/ч |

---

## §3. Access JWT — короткий «пропуск»

### Что в нём лежит (`JwtService.generate`)

```java
return Jwts.builder()
        .issuer(ISSUER)                    // "secure-chat" — кто выдал
        .subject(username)                 // КТО (имя берётся отсюда в чате)
        .id(UUID.randomUUID().toString())  // jti — уникален даже в1 секунду
        .issuedAt(Date.from(now))
        .expiration(Date.from(expiry))     // now + JWT_EXPIRATION_MINUTES (10)
        .claim(CLAIM_TOKEN_VERSION, tokenVersion)  // ver = users.token_version
        .signWith(signingKey)              // HMAC-SHA256 секретом сервера
        .compact();
```

Три важных claim'а:

| Claim | Зачем |
|-------|-------|
| `jti` | Уникальный ID токена. Без него два токена, выданные в одну секунду, были бы **байт-в-байт одинаковы** (мы это поймали на E2E-тесте!) |
| `ver` | «Поколение» токена = `users.token_version`. Подняли число в БД — **все** старые токены пользователя стали невалидными |
| `exp` | Срок жизни. Короткий = маленькое окно утечки |

### Как проверяется (`LocalAuthProvider.validate`)

```java
JwtService.Validated validated = jwtService.validate(token);  // подпись, issuer, exp
User user = userRepository.findByUsername(validated.username())...;

// Токен должен быть выдан при ТЕКУЩЕМ token_version:
if (user.getTokenVersion() != validated.tokenVersion()) {
    throw new InvalidTokenException("Token has been revoked");
}
```

Эта проверка выполняется и для REST, и для **`JOIN` в чат** — поэтому
`/logout` убивает даже уже установленное подключение «при следующем
использовании токена», а по факту — новый JOIN сразу.

**Почему нельзя сделать отзыв «после токена»?** Потому что access-токен
**stateless**: сервер при каждом запросе не хранит список «живых» токенов.
Вместо списка — одно число на пользователя (`token_version`), и токен сам
принозит своё «поколение». Это дёшево (сверка при уже существующем запросе
в БД) и мгновенно.

---

## §4. Refresh token — одноразовый «ключ от сейфа»

### Что выдаётся (`RefreshTokenService.issue`)

```java
String rawRefresh = newRefreshToken();          //32 случайных байта → base64url
RefreshToken stored = new RefreshToken();
stored.setTokenHash(jwtService.hashRefreshToken(rawRefresh)); // HMAC-SHA256!
stored.setFamilyId(familyId);                   // семья этого логина
stored.setUserId(user.getId());
stored.setExpiresAt(now.plus(refreshTokenDays, DAYS));  //30 дней
repository.save(stored);
```

Ключевое: **в БД уходит только хеш** (`token_hash`), сам raw-токен —
только в HTTP-ответе клиенту.

```java
// JwtService — keyed hash секретом сервера
public String hashRefreshToken(String token) {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(signingKey);                       // JWT_SECRET
    return HexFormat.of().formatHex(mac.doFinal(token.getBytes(UTF_8)));
}
```

Почему HMAC, а не простой SHA-256? Утечка БД без `JWT_SECRET` не даёт даже
возможности **проверить угаданный** токен — нужен ключ, которого у ворова нет.

### Ротация (`RefreshTokenService.rotate`) — главный приём

```java
RefreshToken current = findByPlaintext(presented);      // ищем по ХЕШУ

if (current.getRotatedAt() != null || current.getRevokedAt() != null) {
    revokeFamily(current.getFamilyId());                // ← КРАЖА! Отзываем всё
    throw new InvalidTokenException("Refresh token reuse detected; session revoked");
}
if (current.getExpiresAt().isBefore(now)) { ... "expired" ... }

current.setRotatedAt(now);                              // токен СГОРЕЛ
repository.save(current);
return issueInFamily(user, current.getFamilyId(), now); // новый — в ту же семью
```

```
логин:   refresh#1 ──────────────► семья F
refresh: refresh#1 (сгорает) ───► refresh#2 (та же семья F)
refresh: refresh#2 (сгорает) ───► refresh#3 ...
```

**Зачем сжигать старый?** Если старый токен предъявили **второй раз** — это
значит, что он у кого-то украл (у легитимного клиента он уже сгорел).
Показали сгоревший → **семья целиком отзывается** — и у вора, и у жертвы.
Жертва вынуждена залогиниться заново. Это называется **reuse detection**.

### Хранение (миграция `V3__token_revocation.sql`)

```sql
CREATE TABLE refresh_tokens (
    id         BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,   -- HMAC, не сам токен!
    family_id  VARCHAR(36) NOT NULL,          -- семья логина
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP,                    -- NULL = ещё жив
    revoked_at TIMESTAMP                     -- NULL = не отозван
);
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;
```

---

## §5. Два эндпоинта: `/refresh` и `/logout`

```java
// AuthController
@PostMapping("/refresh")   // обмен: старый refresh → новая пара
public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request, ...) {
    if (!rateLimitService.tryConsume("refresh:" + ip, refreshLimit())) throw ...;
    try {
        Issued issued = refreshTokenService.rotate(request.refreshToken());
        return ok(new LoginResponse(...));           // новая пара
    } catch (InvalidTokenException e) {
        return status(401).body(Map.of("error", "INVALID_TOKEN", ...));
    }
}

@PostMapping("/logout")    // отзыв: семья + token_version += 1
public ResponseEntity<Map<String, String>> logout(...) {
    refreshTokenService.revoke(request.refreshToken());
    return ok(Map.of("status", "logged_out"));       // идемпотентно
}
```

`revoke()`:

```java
revokeFamily(current.getFamilyId());                 // все refresh семьями
user.setTokenVersion(user.getTokenVersion() + 1);    // ВСЕ access мертвы сразу
```

Открыт ровно один шаг больше, чем раньше (`SecurityConfig`):

```java
.requestMatchers(HttpMethod.POST,
        "/api/auth/register", "/api/auth/login",
        "/api/auth/refresh", "/api/auth/logout")     // ← эти4 и только они
.permitAll()
.anyRequest().denyAll();                             // всё остальное — отказ
```

---

## §6. Клиент: как это работает для пользователя

`AuthClient` хранит пару и **сам** обновляет access перед истечением:

```java
public synchronized String getValidAccessToken() throws Exception {
    if (System.currentTimeMillis() +30_000 >= accessTokenExpiresAt) {
        return refreshTokens() ? accessToken : null;   // за30 секунд до конца
    }
    return accessToken;
}
```

В чате есть команда:

```text
/logout   → authClient.logout() → POST /logout → локальные токены стёрты,
            сервер отозвал семью и поднял token_version → disconnect
```

Также: `ConsoleTui` при входе берёт токен через `getValidAccessToken()`,
а не «когда был логин» — если пользователь посидел на экране логина, токен
может уже остывать.

---

## §7. Сценарии атаки — что делает система

| Что утекло | Что получает атакующий | Что делает система |
|------------|------------------------|--------------------|
| Access-токен | Доступ ≤10 минут (а с `ver` — до первой смены поколения) | Короткий `exp` = маленькое окно |
| Refresh-токен (сырой) | Попытка обменять | Сгоревший/повторный → **вся семья отозвана**, жертва пере-логинивается |
| Утечка **БД** refresh-токенов | Хеши без `JWT_SECRET` | Проверить угаданный токен нельзя (keyed HMAC) |
| Утечка `JWT_SECRET` | Могут фабриковать что угодно | Это уже компрометация сервера — см. `SECURITY.md` |
| Токен после `/logout` | Ничего | `ver` не совпал → `INVALID_TOKEN`, включая `JOIN` |
| Рестарт с пустым `JWT_SECRET` | Ничего | Секрет случаен → все токены умерли (fail-safe) |

**Что НЕ закрыто (честно):** нет поштучного отзыва access-токенов (поэтому
они и короткие), нет logout «по устройству» (logout — глобальный), нет
смены пароля, просроченные строки refresh не чистятся автоматически.
См. `SECURITY.md`, §9, п.4.

---

## §8. Правила запоминания

1. **Два токена = две скорости.** Access часто и коротко; refresh редко и
   долго. Длинное + часто используемое = обязано быть отзываемым.
2. **Refresh одноразовый.** Второй предъявление = кража → отзываем семью.
3. **В БД — только хеш** (keyed HMAC). Сырой токен живёт только у клиента.
4. **Отзыв через одно число** (`token_version`): не список токенов, а
   «поколение», которое токен принозит сам.
5. **`jti`** — чтобы токены не повторялись байт-в-байт.
6. **Fail-safe:** нет секрета — нет работающих токенов (лучше сломать вход,
   чем отдать фабрику токенов).

**Забыл, где что?**

| Вопрос | Файл |
|--------|------|
| «Какие claims в токене?» | `auth/JwtService.java` (`generate`) |
| «Как ротация и reuse detection?» | `auth/RefreshTokenService.java` (`rotate`) |
| «Почему logout убивает access?» | `LocalAuthProvider.validate` + `users.token_version` |
| «Какие пути открыты?» | `config/SecurityConfig.java` |
| «Что в БД?» | `db/migration/V3__token_revocation.sql` |
| «Как клиент обновляет токен?» | `client/AuthClient.getValidAccessToken()` |
| Наглядные тесты | `RefreshTokenServiceTest`, `LocalAuthProviderTest`, `JwtServiceTest` |

---

## §9. Глоссарий

| Термин | Значение |
|--------|----------|
| **Access token** | Короткоживущий токен запросов (JWT,10 мин) |
| **Refresh token** | Долгоживущий одноразовый токен обновления (30 дней) |
| **TTL** | Time To Live — срок жизни токена |
| **jti** | JWT ID — уникальный идентификатор экземпляра токена |
| **ver / token_version** | «Поколение» токена; несовпадение с БД = отзыв |
| **Ротация (rotation)** | Замена refresh-токена новым при каждом использовании |
| **Reuse detection** | Обнаружение повторного предъявления сгоревшего токена = кража → отзыв семьи |
| **Семья (family)** | Набор refresh-токенов одного логина; отзыв по семье |
| **Отзыв (revocation)** | Делает выданный токен невалидным до истечения срока |
| **Idempotent** | Повторный вызов даёт тот же результат (logout с мусором →200) |

---

## §10. Практика

```powershell
# юнит-тесты темы (20 тестов)
.\gradlew.bat test --tests org.ugina.JwtServiceTest `
  --tests org.ugina.RefreshTokenServiceTest --tests org.ugina.LocalAuthProviderTest
```

Что посмотреть руками:

1. `RefreshTokenServiceTest.issueStoresOnlyTheHashAndBindsTheAccessTokenVersion` —
   в БД уходит хеш, а не токен.
2. `RefreshTokenServiceTest.reusingASpentTokenRevokesTheWholeFamily` —
   reuse → семья горит.
3. `LocalAuthProviderTest.validateRejectsTokenFromAnEarlierVersion` —
   устаревшее поколение → отказ.
4. `JwtServiceTest.everyTokenIsUniqueEvenWithinTheSameSecond` — зачем `jti`.

E2E по сети (`AuthFlowE2E`, печатает `AUTH_FLOW_OK`): login → refresh →
повтор старого refresh (401) → logout → JOIN с убитым токеном
(`INVALID_TOKEN`) → новый вход работает.

---

## §11. Ротация identity-ключа (часть B)

### Зачем

RSA-ключ пользователя был прибит к username **навсегда**: утёк приватный
файл — способа заменить ключ не существовало. Это **другой** ключ, чем пароль
и JWT-секрет: им подписываются handshake'ы чата (см.
[`CRYPTO_GUIDE_RU.md`, §3.6](CRYPTO_GUIDE_RU.md)).

### Три правила ротации

1. **Приватный ключ не покидает устройство.** Генерация на клиенте; сервер
   получает только публичную половину — иначе E2E было бы бессмысленно.
2. **Step-up аутентификация.** Требуются И живой access-токен
   (`Authorization: Bearer ...`), И пароль. Украденный десятиминутный токен
   сам по себе ключ не подменит.
3. **Откат при ошибке.** Локальный файл ключа заменяется первым; если сервер
   отказал — старый ключ восстанавливается. Устройство и каталог ключей
   никогда не расходятся.

### Флоу `/rotate-key`

```
ConsoleTui                 AuthClient              AuthController            БД
    │  /rotate-key             │                          │                  │
    │  ввод пароля ───────────►│                          │                  │
    │  load(старый ключ)       │                          │  ← проверка пароля локально
    │  generate() новая пара   │                          │                  │
    │  store(новый ключ) ──────┼─────────────────────────►│ POST /rotate-key │
    │                          │  Bearer + password + pub │  validate(token) │
    │                          │                          │  BCrypt(password)│
    │                          │                          │  UPDATE key ─────► users.public_key
    │                          │◄──────200 key_rotated────┤                  │
    │◄──── «ротировано» ───────┤                          │                  │
    │                          │         (при ошибке сервера: store(старый ключ) — откат)
```

Ключевые места кода:

```java
// AuthController — step-up: токен И пароль
String token = bearerToken(authorization);           // "Bearer <jwt>"
UserPrincipal caller = authProvider.validate(token); // подпись + срок + ver
UserPrincipal updated = authProvider.rotateKey(
        caller.username(), request.password(), request.publicKey);

// LocalAuthProvider — пароль перепроверяется, ключ валидируется
if (!passwordEncoder.matches(safePassword, user.getPasswordHash()))
    throw new AuthenticationException("Invalid username or password");
RsaCrypto.publicKeyFromBase64(publicKey);            // ≥2048, exponent ≥65537
user.setPublicKey(publicKey);                        // обновляем каталог
```

Rate-limit: `/rotate-key` делит **тот же bucket с `/login`**
(`"login:"+ip`, 10/час) — единый бюджет на подбор пароля, а не отдельный.

### Что видят собеседники (и почему нужна самопочинка)

После ротации `GET_KEY` возвращает новый ключ → у пира срабатывает уже
известный флоу TOFU: предупреждение «ключ изменился» → блокировка →
сверка → `/trust`.

Но есть подводный камень: `keyCache` живёт **всё соединение**. Пир, который
уже видел старый ключ, без дополнительной логики получил бы на новом
handshake `BAD_SIGNATURE` — некрасиво и без подсказки `/trust`. Поэтому в
`ChatClientCore` добавлена самопочинка:

```java
boolean verifyPeerSignature(byte[] payload, byte[] signature, String peerName,
                            PublicKey usedKey, PeerKeySource refetch) {
    if (usedKey != null && RsaSignature.verify(payload, signature, usedKey))
        return true;                                 // обычный путь, без сетевых вызовов
    // ключ устарел (ротация) ИЛИ подпись подделана — спрашиваем сервер заново:
    // GET_KEY → проверка PeerTrustStore → при смене ключа явный флоу /trust
    PublicKey fresh = refetch.get(peerName);
    return RsaSignature.verify(payload, signature, fresh);
}
```

Три исхода: ключ был актуален (fast path,0 запросов), ключ устарел (один
`GET_KEY` → предупреждение и `/trust`), подпись подделана (после повтора всё
равно отказ → `BAD_SIGNATURE`).

### Что происходит с уже открытыми сессиями

Существующие E2E-сессии **продолжают работать**: их корень выведен из
handshake и от identity-ключа не зависит. Новые handshake'ы используют новый
ключ. На стороне ротации: новый `JOIN` не нужен (JWT тот же), свой новый
приватный ключ подхватывается при следующем connect.

### Ограничения

- Нельзя «откатить» ротацию на сервере одной командой — только повторная
  ротация (это осознанно: возврат старого ключа сломал бы пиров, уже
  принявших новый).
- Нет уведомления пиров «в лоб» (push): пир узнаёт о смене при следующем
  `GET_KEY`. Воспоминания о старом ключе в `keyCache` лечит самопочинка.
- Смена пароля и ротация ключа — разные операции; смены пароля пока нет
  (`SECURITY.md`, §9, п.4).

### Практика

```powershell
.\gradlew.bat test --tests org.ugina.LocalAuthProviderTest `
  --tests org.ugina.client.SignatureVerifyTest
```

1. `LocalAuthProviderTest.rotateKey*` — step-up, откат «ничего не изменилось»
   при неверном пароле, отказ на кривом ключе.
2. `SignatureVerifyTest.staleCachedKeyIsReplacedByAFreshFetch` — устаревший
   кэш → ровно один refetch → успех; `forgedSignatureFailsEvenAfterRefetch` —
   подделка не проходит.
3. E2E по сети `KeyRotateE2E` (печатает `KEY_ROTATE_E2E_OK`): закреплённый
   старый ключ → ротация → отправка **блокируется** с предупреждением →
   `/trust` → повтор → сообщение доходит.
