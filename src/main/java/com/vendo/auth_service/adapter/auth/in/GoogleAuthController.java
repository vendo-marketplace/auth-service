package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.application.auth.GoogleOAuthService;
import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.adapter.auth.in.dto.GoogleAuthRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class GoogleAuthController {

    private final GoogleOAuthService googleOAuthService;

    @PostMapping("/google")
    ResponseEntity<AuthResponse> googleAuth(@Valid @RequestBody GoogleAuthRequest googleAuthRequest) {
        return ResponseEntity.ok(googleOAuthService.googleAuth(googleAuthRequest));
    }

}
