package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.auth.in.dto.GoogleAuthRequest;
import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class GoogleOAuthService {

    private final TokenGenerationPort tokenGenerationPort;
    private final GoogleTokenVerifierPort googleTokenVerifierPort;
    private final UserCommandPort userCommandPort;
    private final UserQueryPort userQueryPort;

    @Transactional
    public AuthResponse googleAuth(GoogleAuthRequest googleAuthRequest) {
        GoogleTokenPayload payload = googleTokenVerifierPort.verify(googleAuthRequest.idToken());
        User user = requireUser(payload.email(), payload.fullName());

        TokenPayload tokenPayload = tokenGenerationPort.generate(user);
        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    private User requireUser(String email, String fullName) {
        try {
            return userQueryPort.getByEmail(email);
        } catch (UserNotFoundException e) {
            SaveUserRequest request = SaveUserRequest.builder()
                    .email(email)
                    .fullName(fullName)
                    .roles(Set.of(UserRole.USER))
                    .status(UserStatus.ACTIVE)
                    .providerType(ProviderType.GOOGLE)
                    .build();
            return userCommandPort.save(request);
        }
    }
}
