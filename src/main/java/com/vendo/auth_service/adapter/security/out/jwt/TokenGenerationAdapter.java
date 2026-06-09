package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.port.security.TokenGenerationPort;
import com.vendo.security_lib.type.TokenClaim;
import com.vendo.security_starter.jwt.JwtPayload;
import com.vendo.security_starter.jwt.JwtService;
import com.vendo.user_lib.type.UserRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenGenerationAdapter implements TokenGenerationPort {

    private final JwtProperties jwtProperties;

    @Override
    public TokenPayload generate(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User is required.");
        }

        String accessToken = generateAccessToken(user);
        String refreshToken = generateRefreshToken(user.email());

        return TokenPayload.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private String generateAccessToken(User user) {
        JwtProperties.Secret secret = jwtProperties.getSecret();

        Map<String, Object> claims = Map.of(
                TokenClaim.ID.getClaim(), user.id(),
                TokenClaim.EMAIL.getClaim(), user.email(),
                TokenClaim.VERIFIED.getClaim(), user.emailVerified(),
                TokenClaim.ROLES.getClaim(), user.roles().stream().map(UserRole::name).toList(),
                TokenClaim.STATUS.getClaim(), user.status()
        );

        JwtPayload jwtPayload = JwtPayload.builder()
                .subject(user.email())
                .claims(claims)
                .expiration(secret.accessExpirationTime())
                .build();
        return JwtService.buildToken(jwtPayload, secret.key());
    }

    private String generateRefreshToken(String subject) {
        JwtProperties.Secret secret = jwtProperties.getSecret();

        JwtPayload jwtPayload = JwtPayload.builder()
                .subject(subject)
                .claims(Map.of())
                .expiration(secret.refreshExpirationTime())
                .build();

        return JwtService.buildToken(jwtPayload, secret.key());
    }

}
