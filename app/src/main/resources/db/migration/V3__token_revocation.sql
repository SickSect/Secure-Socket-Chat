-- Point 3: refresh-token revocation.
--
-- The V2 table stored refresh tokens in PLAINTEXT, had no rotation/revocation
-- columns and was never written to by any code, so it is replaced instead of
-- altered. New design:
--   * token_hash — HMAC-SHA256 of the token (a DB leak no longer yields live
--     refresh tokens);
--   * family_id  — all refresh tokens issued in one login session belong to
--     one family, so reuse detection can revoke the whole session;
--   * rotated_at — one-time use: a token can be exchanged exactly once;
--   * revoked_at — explicit revocation (logout / reuse detection).
--
-- users.token_version backs the `ver` claim of access JWTs: bumping it
-- invalidates EVERY outstanding access token for that user immediately
-- (used by logout).

DROP TABLE IF EXISTS refresh_tokens;

CREATE TABLE refresh_tokens
(
    id         BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64)  NOT NULL UNIQUE,
    family_id  VARCHAR(36)  NOT NULL,
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMP    NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

ALTER TABLE users
    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;
