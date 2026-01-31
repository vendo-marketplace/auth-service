package com.vendo.auth_service.application.google;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.auth_service.adapter.in.web.dto.AuthResponse;
import com.vendo.auth_service.adapter.in.web.dto.GoogleAuthRequest;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final TokenGenerationService tokenGenerationService;

    private final GoogleTokenVerifier googleTokenVerifier;

    private final UserCommandPort userCommandPort;

    // TODO write interface
    public AuthResponse googleAuth(GoogleAuthRequest googleAuthRequest) {
        GoogleIdToken.Payload payload = googleTokenVerifier.verify(googleAuthRequest.idToken());
        User user = userCommandPort.ensureExists(payload.getEmail());

        if (user.getStatus() == UserStatus.INCOMPLETE) {
            userCommandPort.update(user.id(), UpdateUserRequest.builder()
                    .status(UserStatus.ACTIVE)
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
