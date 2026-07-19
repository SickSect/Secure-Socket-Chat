package org.ugina.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.ugina.Dto.*;
import org.ugina.auth.*;
import org.ugina.auth.exceptions.AuthenticationException;
import org.ugina.auth.exceptions.InvalidTokenException;
import org.ugina.entity.User;
import org.ugina.ratelimit.RateLimitExceededException;
import org.ugina.ratelimit.RateLimitService;
import org.ugina.repository.UserRepository;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthProvider authProvider;
    private final RateLimitService rateLimitService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    public AuthController(AuthProvider authProvider,
                          RateLimitService rateLimitService,
                          UserRepository userRepository,
                          RefreshTokenService refreshTokenService, JwtService jwtService) {
        this.authProvider = authProvider;
        this.rateLimitService = rateLimitService;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
    }


    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request,
                                                        HttpServletRequest httpRequest) {

        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("register:" + ip, rateLimitService.registerLimit())) {
            throw new RateLimitExceededException("Too many registration attempts. Try again later.");
        }
        UserPrincipal principal = authProvider.register(
                request.username(),
                request.password(),
                request.publicKey()
        );

        // Пока ничего не делаем, но теперь можем посмотреть что пришло
        System.out.println("[register] received: username=" + request.username()
                + ", publicKey length="
                + (request.publicKey() != null ? request.publicKey().length() : 0));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "status", "registered",
                "username", principal.username()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest) throws AuthenticationException {
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitService.tryConsume("login:" + ip, rateLimitService.loginLimit())) {
            throw new RateLimitExceededException("Too many login attempts. Try again later.");
        }
        AuthToken token = authProvider.authenticate(request.username(), request.password());
        User user = userRepository.findByUsername(request.username()).orElseThrow(() -> new AuthenticationException("Invalid username or password"));
        String refreshToken = refreshTokenService.create(user.getId());
        return ResponseEntity.ok(new LoginResponse(token.value(), refreshToken, token.expiresAt()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@Valid @RequestBody RefreshRequest request) throws InvalidTokenException, AuthenticationException {
        Long userId = refreshTokenService.validateAndGetUserId(request.refreshToken());
        User user = userRepository.findById(userId).orElseThrow(() -> new InvalidTokenException("Token references unknown user"));
        AuthToken authToken = jwtService.generateToken(user.getUsername());
        return ResponseEntity.ok(new RefreshResponse(
                authToken.value(),
                authToken.expiresAt()));
    }
}
