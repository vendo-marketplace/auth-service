package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.adapter.auth.out.mapper.AuthMapper;
import com.vendo.auth_service.adapter.auth.in.dto.AuthRequest;
import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.adapter.auth.in.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.auth.in.dto.RefreshRequest;
import com.vendo.auth_service.application.auth.dto.UserResponse;
import com.vendo.auth_service.port.auth.usecase.AuthUseCase;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthUseCase authUseCase;

    private final AuthMapper authMapper;

    private final UserMapper userMapper;

    @PostMapping("/sign-in")
    ResponseEntity<AuthResponse> signIn(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authUseCase.signIn(authMapper.toCommand(request)));
    }

    @PostMapping("/sign-up")
    ResponseEntity<AuthResponse> signUp(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authUseCase.signUp(authMapper.toCommand(request)));
    }

    @PatchMapping("/complete")
    void complete(@Valid @RequestBody CompleteAuthRequest request) {
        authUseCase.complete(authMapper.toCompleteCommand(request));
    }

    @PostMapping("/refresh")
    ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        return ResponseEntity.ok(authUseCase.refresh(authMapper.toRefreshCommand(refreshRequest)));
    }

    @GetMapping("/me")
    ResponseEntity<UserResponse> getAuthenticatedUser() {
        return ResponseEntity.ok(userMapper.toResponse(authUseCase.me()));
    }

}
