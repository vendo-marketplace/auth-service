package com.vendo.auth_service.adapter.in.web.controller;

import com.vendo.auth_service.adapter.in.security.dto.AuthUser;
import com.vendo.auth_service.adapter.in.web.dto.AuthRequest;
import com.vendo.auth_service.adapter.in.web.dto.AuthResponse;
import com.vendo.auth_service.adapter.in.web.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.in.web.dto.RefreshRequest;
import com.vendo.auth_service.application.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-in")
    ResponseEntity<AuthResponse> signIn(@Valid @RequestBody AuthRequest authRequest) {
        return ResponseEntity.ok(authService.signIn(authRequest));
    }

    @PostMapping("/sign-up")
    void signUp(@Valid @RequestBody AuthRequest authRequest) {
        authService.signUp(authRequest);
    }

    @PatchMapping("/complete-auth")
    void completeAuth(
            @RequestParam String email,
            @Valid @RequestBody CompleteAuthRequest completeAuthRequest
    ) {
        authService.completeAuth(email, completeAuthRequest);
    }

    @PostMapping("/refresh")
    ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok(authService.refresh(refreshRequest));
    }

    @GetMapping("/me")
    ResponseEntity<AuthUser> getAuthenticatedUserProfile() {
        return ResponseEntity.ok(authService.getAuthenticatedUserProfile());
    }
}
