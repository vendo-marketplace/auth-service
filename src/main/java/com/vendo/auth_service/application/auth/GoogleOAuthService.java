package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.application.auth.dto.*;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.GoogleAuthCodePort;
import com.vendo.auth_service.port.auth.GoogleTokenVerifierPort;
import com.vendo.auth_service.port.auth.usecase.GoogleAuthUseCase;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.core_lib.utils.StringUtils;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
class GoogleOAuthService implements GoogleAuthUseCase {

    private final GoogleAuthCodePort googleAuthCodePort;
    private final GoogleTokenVerifierPort googleTokenVerifierPort;

    private final TokenGenerationPort tokenGenerationPort;
    private final UserCommandPort userCommandPort;
    private final UserQueryPort userQueryPort;

    @Override
    public AuthResponse auth(String authCode) {
        String idToken = googleAuthCodePort.exchange(authCode);
        GoogleTokenPayload payload = googleTokenVerifierPort.verify(idToken);

        User user = requireUser(payload);
        TokenPayload tokenPayload = tokenGenerationPort.generate(user);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    private User requireUser(GoogleTokenPayload payload) {
        String fullName = User.isValidFullName(payload.fullName()) ? payload.fullName() : null;

        return findByEmail(payload.email())
                .map(user -> completeFullName(user, fullName))
                .orElseGet(() -> save(payload.email(), fullName));
    }

    private Optional<User> findByEmail(String email) {
        try {
            return Optional.of(userQueryPort.getByEmail(email));
        } catch (UserNotFoundException e) {
            return Optional.empty();
        }
    }

    private User completeFullName(User user, String fullName) {
        if (user.isCompleted() || StringUtils.isEmpty(fullName)) {
            return user;
        }

        userCommandPort.update(user.id(), UpdateUserRequest.builder().fullName(fullName).build());
        return user.withFullName(fullName);
    }

    private User save(String email, String fullName) {
        SaveUserRequest request = SaveUserRequest.builder()
                .email(email)
                .fullName(fullName)
                .roles(Set.of(UserRole.USER))
                .emailVerified(true)
                .status(UserStatus.ACTIVE)
                .providerType(ProviderType.GOOGLE)
                .build();
        return userCommandPort.save(request);
    }
}
