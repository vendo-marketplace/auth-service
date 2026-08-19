package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.port.auth.usecase.GoogleAuthUseCase;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class GoogleAuthController {

    private final GoogleAuthUseCase googleAuth;

    @PostMapping("/google")
    ResponseEntity<AuthResponse> googleAuth(
            @Valid
            @NotBlank(message = "Auth code is required.")
            @RequestParam String authCode
    ) {
        return ResponseEntity.ok(googleAuth.auth(authCode));
    }

}
