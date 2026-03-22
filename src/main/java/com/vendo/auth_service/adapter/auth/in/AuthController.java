package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.adapter.auth.out.mapper.AuthMapper;
import com.vendo.auth_service.adapter.auth.in.dto.AuthRequest;
import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.adapter.auth.in.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.RefreshRequest;
import com.vendo.auth_service.application.auth.AuthService;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    private final AuthMapper authMapper;

    @PostMapping("/sign-in")
    ResponseEntity<AuthResponse> signIn(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.signIn(authMapper.toCommand(request)));
    }

    @PostMapping("/sign-up")
    void signUp(@Valid @RequestBody AuthRequest request) {
        authService.signUp(authMapper.toCommand(request));
    }

    @PatchMapping("/complete-auth")
    void completeAuth(
            @RequestParam String email,
            @Valid @RequestBody CompleteAuthRequest request
    ) {
        authService.completeAuth(email, authMapper.toCompleteCommand(request));
    }

    @PostMapping("/refresh")
    ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok(authService.refresh(authMapper.toRefreshCommand(refreshRequest)));
    }

    @GetMapping("/me")
    ResponseEntity<AuthUserResponse> getAuthenticatedUserProfile() {
        return ResponseEntity.ok(authService.getAuthenticatedUserProfile());
    }

}
