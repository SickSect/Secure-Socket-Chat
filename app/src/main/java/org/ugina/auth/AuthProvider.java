package org.ugina.auth;

import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;

public interface AuthProvider {
    /**
     * Регистрирует нового пользователя.
     *
     * @param username  логин пользователя
     * @param password  пароль (в открытом виде, реализация хеширует)
     * @param publicKey RSA-публичный ключ пользователя в Base64
     * @return созданный пользователь
     * @throws RegistrationException если регистрация невозможна
     *                               (имя занято, невалидный ключ и т.д.)
     */
    UserPrincipal register(String username, String password, String publicKey)
            throws RegistrationException;

    /**
     * Аутентифицирует пользователя по логину и паролю.
     *
     * @param username логин
     * @param password пароль в открытом виде
     * @return токен для использования в последующих запросах
     * @throws AuthenticationException если логин/пароль неверны
     */
    AuthToken authenticate(String username, String password)
            throws AuthenticationException;

    /**
     * Проверяет токен и возвращает информацию о пользователе.
     *
     * @param token токен из authenticate()
     * @return данные владельца токена
     * @throws InvalidTokenException если токен невалиден или истёк
     */
    UserPrincipal validate(String token) throws InvalidTokenException;

    /**
     * Заменяет публичный identity-ключ пользователя (ротация ключа).
     * Требует повторной аутентификации паролем (step-up), а не только
     * действующей сессии: украденный access-токен не даёт возможности
     * подменить ключ.
     *
     * @param username  владелец ключа (из валидной сессии)
     * @param password  текущий пароль — доказательство владения аккаунтом
     * @param publicKey новый RSA-публичный ключ в Base64 (≥ 2048)
     * @return обновлённый профиль
     * @throws AuthenticationException если пароль неверен
     * @throws RegistrationException   если ключ некорректен
     */
    UserPrincipal rotateKey(String username, String password, String publicKey)
            throws AuthenticationException, RegistrationException;
}
