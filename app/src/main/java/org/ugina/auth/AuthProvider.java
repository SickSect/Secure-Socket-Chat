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
}
