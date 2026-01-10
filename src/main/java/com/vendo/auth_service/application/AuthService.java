package com.vendo.auth_service.application;

import com.vendo.auth_service.adapter.in.controller.dto.AuthRequest;
import com.vendo.auth_service.adapter.in.controller.dto.AuthResponse;
import com.vendo.auth_service.adapter.in.controller.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.in.controller.dto.RefreshRequest;
import com.vendo.auth_service.domain.user.UserService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.domain.user.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.dto.User;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.JwtClaimsParser;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.domain.user.service.UserActivityPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final TokenGenerationService tokenGenerationService;

    private final BearerTokenExtractor bearerTokenExtractor;

    private final JwtClaimsParser jwtClaimsParser;

    private final PasswordEncoder passwordEncoder;

    private final UserQueryPort userQueryPort;

    private final UserCommandPort userCommandPort;

    private final UserService userService;

    public AuthResponse signIn(AuthRequest authRequest) {
        User user = userQueryPort.getByEmail(authRequest.email());
        UserActivityPolicy.validateActivity(user);
        matchPasswordsOrThrow(authRequest.password(), user.password());
        TokenPayload tokenPayload = tokenGenerationService.generateTokensPair(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public void signUp(AuthRequest authRequest) {
        userQueryPort.getByEmail(authRequest.email());

        String encodedPassword = passwordEncoder.encode(authRequest.password());

        userCommandPort.save(SaveUserRequest.builder()
                .email(authRequest.email())
                .status(UserStatus.INCOMPLETE)
                .providerType(ProviderType.LOCAL)
                .password(encodedPassword)
                .emailVerified(false)
                .build());
    }

    public void completeAuth(String email, CompleteAuthRequest completeAuthRequest) {
        User user = userQueryPort.getByEmail(email);

        userService.validateBeforeActivation(user);

        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .status(UserStatus.ACTIVE)
                .fullName(completeAuthRequest.fullName())
                .birthDate(completeAuthRequest.birthDate()).build());
    }

    public AuthResponse refresh(RefreshRequest refreshRequest) {
        String token = bearerTokenExtractor.parseBearerToken(refreshRequest.refreshToken());
        String email = jwtClaimsParser.parseEmailFromToken(token);

        User user = userQueryPort.getByEmail(email);
        TokenPayload tokenPayload = tokenGenerationService.generateTokensPair(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    private void matchPasswordsOrThrow(String rawPassword, String encodedPassword) {
        boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);
        if (!matches) {
            throw new BadCredentialsException("Wrong credentials");
        }
    }
}
