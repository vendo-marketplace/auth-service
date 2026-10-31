package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.adapter.auth.out.mapper.AuthMapper;
import com.vendo.auth_service.adapter.auth.in.dto.AuthRequest;
import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
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

    private final AuthMapper authMapper;
    private final AuthUseCase authUseCase;

    private final UserMapper userMapper;

    @PostMapping("/sign-in")
    ResponseEntity<Void> signIn(@Valid @RequestBody AuthRequest request) {
        authUseCase.signIn(authMapper.toCommand(request));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/sign-up")
    ResponseEntity<Void> signUp(@Valid @RequestBody AuthRequest request) {
        authUseCase.signUp(authMapper.toCommand(request));
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/complete")
    void complete(@Valid @RequestBody CompleteAuthRequest request) {
        authUseCase.complete(authMapper.toCompleteCommand(request));
    }

    @PostMapping("/refresh")
    ResponseEntity<Void> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        authUseCase.refresh(authMapper.toRefreshCommand(refreshRequest));
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    ResponseEntity<UserResponse> getAuthenticatedUser() {
        return ResponseEntity.ok(userMapper.toResponse(authUseCase.me()));
    }

}
