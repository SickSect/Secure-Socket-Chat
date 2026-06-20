package org.ugina.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.ugina.Dto.LoginRequest;
import org.ugina.Dto.LoginResponse;
import org.ugina.Dto.RegisterRequest;
import org.ugina.auth.AuthProvider;
import org.ugina.auth.AuthToken;
import org.ugina.auth.UserPrincipal;
import org.ugina.auth.exceptions.AuthenticationException;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthProvider authProvider;

    public AuthController(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request) {
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
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) throws AuthenticationException {
        AuthToken token = authProvider.authenticate(request.username(), request.password());
        return ResponseEntity.ok(new LoginResponse(token.value(), token.expiresAt()));
    }
}
