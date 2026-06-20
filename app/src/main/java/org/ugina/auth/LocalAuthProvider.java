package org.ugina.auth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;
import org.ugina.crypto.RsaCrypto;
import org.ugina.entity.User;
import org.ugina.repository.UserRepository;
import org.ugina.utils.CustomLogger;

import java.util.Optional;

@Service
@ConditionalOnProperty(name = "auth.provider", havingValue = "local", matchIfMissing = true)
public class LocalAuthProvider implements AuthProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public LocalAuthProvider(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Override
    public UserPrincipal register(String username, String password, String publicKey)
            throws RegistrationException {
        if (userRepository.findByUsername(username).isPresent()) {
            CustomLogger.logInfo("User already exists " + username, LocalAuthProvider.class.getName());
            throw new RegistrationException("User already exists");
        }
        try{
            RsaCrypto.publicKeyFromBase64(publicKey);
        }catch (Exception e){
            CustomLogger.logInfo("Invalid public key for user " + username, LocalAuthProvider.class.getName());
            throw new RegistrationException("Invalid public key format", e);
        }
        String passwordHash = passwordEncoder.encode(password);
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordHash);
        user.setPublicKey(publicKey);
        User savedUser = userRepository.save(user);
        return new UserPrincipal(savedUser.getUsername(), savedUser.getPublicKey());
    }

    @Override
    public AuthToken authenticate(String username, String password)
            throws AuthenticationException {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            CustomLogger.logInfo("DEBUG: user NOT FOUND: '" + username + "'", LocalAuthProvider.class.getName());
            throw new AuthenticationException("Invalid username or password");
        }
        User user = userOpt.get();
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            CustomLogger.logInfo("DEBUG: password MISMATCH for: '" + username + "'", LocalAuthProvider.class.getName());
            throw new AuthenticationException("Invalid username or password");
        }
        // Generate token
        String token = jwtService.generate(username);
        long expiresAt = jwtService.getExpirationMillis();
        return new AuthToken(token, expiresAt);
    }

    @Override
    public UserPrincipal validate(String token) throws InvalidTokenException {
        // 1. Проверяем JWT и достаём username
        String username;
        try {
            username = jwtService.validateAndGetUsername(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid or expired token", e);
        }

        // 2. Находим пользователя в БД (нужен publicKey)
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new InvalidTokenException(
                        "Token references unknown user: " + username));

        // 3. Возвращаем principal
        return new UserPrincipal(user.getUsername(), user.getPublicKey());
    }
}
