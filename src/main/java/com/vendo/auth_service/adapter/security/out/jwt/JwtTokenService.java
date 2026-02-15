package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.adapter.security.out.jwt.utils.JwtUtils;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.security.common.exception.InvalidTokenException;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static com.vendo.security.common.type.TokenClaim.*;

@Component
@RequiredArgsConstructor
public class JwtTokenService implements TokenGenerationService {

    private final JwtUtils jwtUtils;

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

    public Claims extractAllClaims(String token, String secretKey) {
        try {
            return jwtUtils.parseSignedClaims(token, secretKey).getPayload();
        } catch (JwtException e) {
            throw new InvalidTokenException(e.getMessage());
        }
    }

    private String generateAccessToken(User user) {
        Map<String, Object> claims = Map.of(
                USER_ID_CLAIM.getClaim(), user.id(),
                EMAIL_VERIFIED_CLAIM.getClaim(), user.emailVerified(),
                ROLES_CLAIM.getClaim(), List.of(user.role().name()),
                STATUS_CLAIM.getClaim(), user.getStatus()
        );

        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(user.email())
                .claims(claims)
                .expiration(jwtProperties.getAccessExpiration())
                .build();
        return jwtUtils.buildToken(jwtProperties.getKey(), jwtPayload);
    }

    private String generateRefreshToken(String subject) {
        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(subject)
                .claims(Map.of())
                .expiration(jwtProperties.getAccessExpiration())
                .build();

        return jwtUtils.buildToken(jwtProperties.getKey(), jwtPayload);
    }
}
