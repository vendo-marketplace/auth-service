package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.domain.auth.dto.AuthRequest;
import com.vendo.auth_service.domain.auth.dto.AuthResponse;
import com.vendo.auth_service.domain.auth.dto.CompleteAuthRequest;
import com.vendo.auth_service.domain.auth.dto.RefreshRequest;
import com.vendo.auth_service.domain.auth.dto.AuthUser;
import com.vendo.auth_service.domain.user.service.UserService;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import com.vendo.auth_service.port.security.*;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.domain.user.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.domain.auth.dto.TokenPayload;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.domain.user.service.UserActivityPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserQueryPort userQueryPort;

    private final UserCommandPort userCommandPort;

    private final UserService userService;

    private final UserAuthenticationService userAuthenticationService;

    private final TokenGenerationService tokenGenerationService;

    private final BearerTokenExtractor bearerTokenExtractor;

    private final PasswordHashingPort passwordHashingPort;

    private final JwtClaimsParser jwtClaimsParser;

    public AuthResponse signIn(AuthRequest authRequest) {
        User user = userQueryPort.getByEmail(authRequest.email());
        UserActivityPolicy.validateActivity(user);
        matchPasswordsOrThrow(passwordHashingPort.matches(authRequest.password(), user.password()));
        TokenPayload tokenPayload = tokenGenerationService.generate(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public void signUp(AuthRequest authRequest) {
        userService.throwIfExists(userQueryPort.existsByEmail(authRequest.email()));
        String hashedPassword = passwordHashingPort.hash(authRequest.password());

        userCommandPort.save(SaveUserRequest.builder()
                .email(authRequest.email())
                .status(UserStatus.INCOMPLETE)
                .role(UserRole.USER)
                .providerType(ProviderType.LOCAL)
                .password(hashedPassword)
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
        String token = bearerTokenExtractor.parse(refreshRequest.refreshToken());
        String email = jwtClaimsParser.extractEmail(token);
        User user = userQueryPort.getByEmail(email);
        TokenPayload tokenPayload = tokenGenerationService.generate(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public AuthUser getAuthenticatedUserProfile() {
        return userAuthenticationService.getAuthUser();
    }

    private void matchPasswordsOrThrow(boolean b) {
        if (!b) {
            throw new BadCredentialsException("Wrong credentials");
        }
    }

}
