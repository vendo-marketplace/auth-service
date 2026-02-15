package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.application.auth.command.AuthCommand;
import com.vendo.auth_service.application.auth.command.CompleteAuthCommand;
import com.vendo.auth_service.application.auth.command.RefreshCommand;
import com.vendo.auth_service.domain.user.service.UserService;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import com.vendo.auth_service.port.security.*;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
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

    private final TokenClaimsParser tokenClaimsParser;

    public AuthResponse signIn(AuthCommand command) {
        User user = userQueryPort.getByEmail(command.email());
        UserActivityPolicy.validateActivity(user);
        matchPasswordsOrThrow(passwordHashingPort.matches(command.password(), user.password()));
        TokenPayload tokenPayload = tokenGenerationService.generate(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public void signUp(AuthCommand command) {
        userService.throwIfExists(userQueryPort.existsByEmail(command.email()));
        String hashedPassword = passwordHashingPort.hash(command.password());

        userCommandPort.save(User.builder()
                .email(command.email())
                .status(UserStatus.INCOMPLETE)
                .role(UserRole.USER)
                .providerType(ProviderType.LOCAL)
                .password(hashedPassword)
                .emailVerified(false)
                .build());
    }

    public void completeAuth(String email, CompleteAuthCommand command) {
        User user = userQueryPort.getByEmail(email);
        userService.validateBeforeActivation(user);

        userCommandPort.update(user.id(), User.builder()
                .status(UserStatus.ACTIVE)
                .fullName(command.fullName())
                .birthDate(command.birthDate()).build());
    }

    public AuthResponse refresh(RefreshCommand command) {
        String token = bearerTokenExtractor.extract(command.refreshToken());
        String email = tokenClaimsParser.extractSubject(token);
        User user = userQueryPort.getByEmail(email);
        TokenPayload tokenPayload = tokenGenerationService.generate(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public AuthUserResponse getAuthenticatedUserProfile() {
        return userAuthenticationService.getAuthUser();
    }

    private void matchPasswordsOrThrow(boolean b) {
        if (!b) {
            throw new BadCredentialsException("Wrong credentials.");
        }
    }

}
