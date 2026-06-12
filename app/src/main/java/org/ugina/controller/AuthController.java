package org.ugina.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.ugina.Dto.Req.RegisterRequest;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest request) {
        // Пока ничего не делаем, но теперь можем посмотреть что пришло
        System.out.println("[register] received: username=" + request.username()
                + ", publicKey length="
                + (request.publicKey() != null ? request.publicKey().length() : 0));

        return ResponseEntity.ok(Map.of(
                "status", "received",
                "message", "Registration endpoint is alive",
                "username", request.username() != null ? request.username() : "(null)"
        ));
    }
}
