package com.vendo.auth_service.application.google;

import com.vendo.auth_service.domain.google.GoogleTokenPayload;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.security.TokenPayload;
import com.vendo.auth_service.port.google.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.domain.security.AuthResponse;
import com.vendo.auth_service.domain.google.GoogleAuthRequest;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final TokenGenerationService tokenGenerationService;

    private final GoogleTokenVerifierPort googleTokenVerifierPort;

    private final UserCommandPort userCommandPort;

    // TODO write interface
    public AuthResponse googleAuth(GoogleAuthRequest googleAuthRequest) {
        GoogleTokenPayload payload = googleTokenVerifierPort.verify(googleAuthRequest.idToken());
        User user = userCommandPort.ensureExists(payload.email());

        if (user.getStatus() == UserStatus.INCOMPLETE) {
            userCommandPort.update(user.id(), UpdateUserRequest.builder()
                    .status(UserStatus.ACTIVE)
                    .fullName(payload.fullName())
                    .providerType(ProviderType.GOOGLE).build()
            );
        }

        TokenPayload tokenPayload = tokenGenerationService.generate(user);
        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }
}
