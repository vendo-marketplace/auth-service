package com.vendo.auth_service.service.auth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.vendo.auth_service.http.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.http.user.dto.UserInfo;
import com.vendo.auth_service.security.common.dto.TokenPayload;
import com.vendo.auth_service.security.service.TokenGenerationService;
import com.vendo.auth_service.web.dto.AuthResponse;
import com.vendo.auth_service.web.dto.GoogleAuthRequest;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final TokenGenerationService tokenGenerationService;


    private final GoogleTokenVerifier googleTokenVerifier;

    public AuthResponse googleAuth(GoogleAuthRequest googleAuthRequest) {
        GoogleIdToken.Payload payload = googleTokenVerifier.verify(googleAuthRequest.idToken());

        UserInfo userInfo = userInfoProvider.ensureExists(payload.getEmail());

        if (userInfo.getStatus() == UserStatus.INCOMPLETE) {
            userInfoProvider.update(userInfo.email(), UpdateUserInfoRequest.builder()
                    .status(UserStatus.ACTIVE)
                    .providerType(ProviderType.GOOGLE).build()
            );
        }

        TokenPayload tokenPayload = tokenGenerationService.generateTokensPair(userInfo);
        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }
}
