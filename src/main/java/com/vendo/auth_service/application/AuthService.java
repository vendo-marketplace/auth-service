package com.vendo.auth_service.application;

import com.vendo.auth_service.adapter.in.controller.dto.AuthRequest;
import com.vendo.auth_service.adapter.in.controller.dto.AuthResponse;
import com.vendo.auth_service.adapter.in.controller.dto.CompleteAuthRequest;
import com.vendo.auth_service.adapter.in.controller.dto.RefreshRequest;
import com.vendo.auth_service.adapter.out.user.exception.UserInfoAlreadyExistsException;
import com.vendo.auth_service.port.user.UserInfoCommandPort;
import com.vendo.auth_service.port.user.UserInfoQueryPort;
import com.vendo.auth_service.adapter.out.user.dto.SaveUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UserInfo;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.JwtClaimsParser;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.domain.user.service.UserActivityPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserActivityValidationService userActivityValidationService;

    private final TokenGenerationService tokenGenerationService;

    private final BearerTokenExtractor bearerTokenExtractor;

    private final JwtClaimsParser jwtClaimsParser;

    private final PasswordEncoder passwordEncoder;

    private final UserInfoQueryPort userInfoQueryPort;

    private final UserInfoCommandPort userInfoCommandPort;

    public AuthResponse signIn(AuthRequest authRequest) {
        UserInfo userInfo = getUserInfoOrThrowIfNotFound(authRequest.email());
        UserActivityPolicy.validateActivity(userInfo);
        matchPasswordsOrThrow(authRequest.password(), userInfo.password());
        TokenPayload tokenPayload = tokenGenerationService.generateTokensPair(userInfo);

        return AuthResponse.builder()
                .accessToken(tokenPayload.accessToken())
                .refreshToken(tokenPayload.refreshToken())
                .build();
    }

    public void signUp(AuthRequest authRequest) {
        throwIfUserInfoAlreadyExists(authRequest.email());

        String encodedPassword = passwordEncoder.encode(authRequest.password());

        userInfoCommandPort.save(SaveUserInfoRequest.builder()
                .email(authRequest.email())
                .status(UserStatus.INCOMPLETE)
                .providerType(ProviderType.LOCAL)
                .password(encodedPassword)
                .emailVerified(false)
                .build());
    }

    public void completeAuth(String email, CompleteAuthRequest completeAuthRequest) {
        UserInfo userInfo = getUserInfoOrThrowIfNotFound(email);

//        userActivityValidationService.validateBeforeActivation(user);

        userInfoCommandPort.update(userInfo.id(), UpdateUserInfoRequest.builder()
                .status(UserStatus.ACTIVE)
                .fullName(completeAuthRequest.fullName())
                .birthDate(completeAuthRequest.birthDate()).build());
    }

    public AuthResponse refresh(RefreshRequest refreshRequest) {
        String token = bearerTokenExtractor.parseBearerToken(refreshRequest.refreshToken());
        String email = jwtClaimsParser.parseEmailFromToken(token);

        UserInfo userInfo = getUserInfoOrThrowIfNotFound(email);
        TokenPayload tokenPayload = tokenGenerationService.generateTokensPair(userInfo);

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

    private UserInfo getUserInfoOrThrowIfNotFound(String email) {
        Optional<UserInfo> optionalUserInfo = userInfoQueryPort.findByEmail(email);

        if (optionalUserInfo.isEmpty()) {
            throw new UsernameNotFoundException("User info not found.");
        }

        return optionalUserInfo.get();
    }

    private void throwIfUserInfoAlreadyExists(String email) {
        Optional<UserInfo> optionalUserInfo = userInfoQueryPort.findByEmail(email);

        if (optionalUserInfo.isPresent()) {
            throw new UserInfoAlreadyExistsException("User info already exists.");
        }
    }

}
