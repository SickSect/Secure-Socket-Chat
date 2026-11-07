package org.ugina.auth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.auth.exceptions.RegistrationException;
import org.ugina.crypto.RsaCrypto;
import org.ugina.entity.User;
import org.ugina.repository.UserRepository;
import org.ugina.utils.CustomLogger;
import org.ugina.utils.UsernamePolicy;

import java.util.Optional;

@Service
@ConditionalOnProperty(name = "auth.provider", havingValue = "local", matchIfMissing = true)
public class LocalAuthProvider implements AuthProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    /**
     * A real BCrypt hash used for unknown usernames so that a failed login
     * takes roughly the same time whether the user exists or not.
     */
    private final String dummyPasswordHash;

    public LocalAuthProvider(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenService refreshTokenService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.dummyPasswordHash = passwordEncoder.encode(
                "dummy-password-only-for-constant-time-login");
    }

    @Override
    public UserPrincipal register(String username, String password, String publicKey)
            throws RegistrationException {
        if (!UsernamePolicy.isValid(username)) {
            throw new RegistrationException(
                    "Username must be 1-" + UsernamePolicy.MAX_LENGTH
                            + " characters and contain only letters, digits and underscores");
        }
        if (password == null || password.isBlank()) {
            throw new RegistrationException("Password must not be blank");
        }
        if (publicKey == null || publicKey.isBlank()) {
            throw new RegistrationException("Public key must not be blank");
        }

        try {
            RsaCrypto.publicKeyFromBase64(publicKey);
        } catch (Exception e) {
            CustomLogger.logInfo("Rejected invalid public key during registration",
                    LocalAuthProvider.class.getName());
            throw new RegistrationException("Invalid public key format", e);
        }

        if (userRepository.findByUsername(username).isPresent()) {
            throw new RegistrationException("User already exists");
        }

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setPublicKey(publicKey);

        try {
            User savedUser = userRepository.save(user);
            return new UserPrincipal(savedUser.getUsername(), savedUser.getPublicKey());
        } catch (DataIntegrityViolationException e) {
            // Two concurrent registrations for the same name: the unique
            // constraint is the real arbiter.
            throw new RegistrationException("User already exists", e);
        }
    }

    @Override
    public AuthToken authenticate(String username, String password)
            throws AuthenticationException {
        String safePassword = password == null ? "" : password;
        Optional<User> userOpt = username == null
                ? Optional.empty()
                : userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            // Equalise timing with the "user exists" branch.
            passwordEncoder.matches(safePassword, dummyPasswordHash);
            throw new AuthenticationException("Invalid username or password");
        }

        User user = userOpt.get();
        if (!passwordEncoder.matches(safePassword, user.getPasswordHash())) {
            throw new AuthenticationException("Invalid username or password");
        }

        RefreshTokenService.Issued issued = refreshTokenService.issue(user);
        return new AuthToken(
                issued.accessToken(),
                issued.accessExpiresAt(),
                issued.refreshToken(),
                issued.refreshExpiresAt());
    }

    @Override
    public UserPrincipal validate(String token) throws InvalidTokenException {
        JwtService.Validated validated;
        try {
            validated = jwtService.validate(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid or expired token", e);
        }

        User user = userRepository.findByUsername(validated.username())
                .orElseThrow(() -> new InvalidTokenException(
                        "Token references unknown user"));

        // The token must have been minted under the user's current version.
        // Logout (and any future compromise response) bumps the version, which
        // kills every previously issued access token immediately.
        if (user.getTokenVersion() != validated.tokenVersion()) {
            throw new InvalidTokenException("Token has been revoked");
        }

        return new UserPrincipal(user.getUsername(), user.getPublicKey());
    }

    /**
     * Replaces the user's public identity key after password re-authentication
     * (step-up). The private half never touches the server: the client
     * generates the pair locally and only publishes the new public key.
     *
     * <p>Afterwards every peer's next {@code GET_KEY} returns the new key,
     * which the peer's TOFU store flags as a change — messages stay blocked
     * until the peer verifies the fingerprint out of band and runs
     * {@code /trust}.</p>
     */
    @Override
    public UserPrincipal rotateKey(String username, String password, String publicKey)
            throws AuthenticationException, RegistrationException {
        if (!UsernamePolicy.isValid(username)) {
            throw new RegistrationException("Invalid username");
        }
        String safePassword = password == null ? "" : password;
        if (password == null || password.isBlank()) {
            throw new AuthenticationException("Password is required");
        }
        if (publicKey == null || publicKey.isBlank()) {
            throw new RegistrationException("Public key must not be blank");
        }
        try {
            RsaCrypto.publicKeyFromBase64(publicKey);   // ≥2048, exponent ≥65537
        } catch (Exception e) {
            throw new RegistrationException("Invalid public key format", e);
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            // Same timing equalisation as login.
            passwordEncoder.matches(safePassword, dummyPasswordHash);
            throw new AuthenticationException("Invalid username or password");
        }
        User user = userOpt.get();
        if (!passwordEncoder.matches(safePassword, user.getPasswordHash())) {
            throw new AuthenticationException("Invalid username or password");
        }

        user.setPublicKey(publicKey);
        userRepository.save(user);
        CustomLogger.logInfo("Identity key rotated for " + username,
                LocalAuthProvider.class.getName());
        return new UserPrincipal(user.getUsername(), user.getPublicKey());
    }
}
