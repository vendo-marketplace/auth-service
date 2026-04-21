package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.auth.in.dto.GoogleAuthRequest;
import com.vendo.auth_service.application.auth.dto.AuthResponse;
import com.vendo.auth_service.application.auth.dto.GoogleTokenPayload;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final TokenGenerationService tokenGenerationService;
    private final GoogleTokenVerifierPort googleTokenVerifierPort;
    private final UserCommandPort userCommandPort;

    public AuthResponse googleAuth(GoogleAuthRequest googleAuthRequest) {
        GoogleTokenPayload payload = googleTokenVerifierPort.verify(googleAuthRequest.idToken());
        User user = userCommandPort.ensureExists(payload.email());
        updateIfFirstLogin(user, payload);

        TokenPayload tokenPayload = tokenGenerationService.generate(user);
        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    private void updateIfFirstLogin(User user, GoogleTokenPayload payload) {
        if (Objects.isNull(user.providerType()) && Objects.isNull(user.status())) {
            userCommandPort.update(user.id(), UpdateUserRequest.builder()
                    .status(UserStatus.ACTIVE)
                    .fullName(payload.fullName())
                    .providerType(ProviderType.GOOGLE).build()
            );
        }
    }

}
