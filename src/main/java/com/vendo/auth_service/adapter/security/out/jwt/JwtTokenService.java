package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.adapter.security.out.jwt.utils.JwtUtils;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.auth.dto.TokenPayload;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.security_lib.type.UserTokenClaim;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Slf4j
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
            log.error(e.getMessage());
            throw new BadCredentialsException("Invalid or expired token.");
        }
    }

    private String generateAccessToken(User user) {
        Map<String, Object> claims = Map.of(
                UserTokenClaim.ID.getClaim(), user.id(),
                UserTokenClaim.VERIFIED.getClaim(), user.emailVerified(),
                UserTokenClaim.ROLES.getClaim(), List.of(user.role().name()),
                UserTokenClaim.STATUS.getClaim(), user.status()
        );

        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(user.email())
                .claims(claims)
                .expirationTime(jwtProperties.getAccessExpirationTime())
                .build();
        return jwtUtils.buildToken(jwtProperties.getKey(), jwtPayload);
    }

    private String generateRefreshToken(String subject) {
        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(subject)
                .claims(Map.of())
                .expirationTime(jwtProperties.getRefreshExpirationTime())
                .build();

        return jwtUtils.buildToken(jwtProperties.getKey(), jwtPayload);
    }

}
