package com.vendo.auth_service.adapter.out.security.service;

import com.vendo.auth_service.adapter.out.user.dto.UserInfo;
import com.vendo.auth_service.common.config.JwtProperties;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;
import com.vendo.auth_service.adapter.out.security.helper.JwtHelper;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.JwtClaimsParser;
import com.vendo.auth_service.port.security.TokenGenerationService;
import com.vendo.security.common.exception.InvalidTokenException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;
import static com.vendo.security.common.type.TokenClaim.*;

@Service
@RequiredArgsConstructor
public class JwtService implements TokenGenerationService, BearerTokenExtractor, JwtClaimsParser {

    private final JwtHelper jwtHelper;

    private final JwtProperties jwtProperties;

    @Override
    public String parseBearerToken(String jwtToken) {
        if (!jwtToken.startsWith(BEARER_PREFIX)) {
            throw new InvalidTokenException("Invalid token.");
        }

        return jwtToken.substring(BEARER_PREFIX.length());
    }

    @Override
    public String parseEmailFromToken(String jwtToken) {
        return jwtHelper.extractAllClaims(jwtToken).getSubject();
    }

    @Override
    public TokenPayload generateTokensPair(UserInfo userInfo) {
        if (userInfo == null) {
            throw new IllegalArgumentException("User info is required.");
        }

        String accessToken = generateAccessToken(userInfo);
        String refreshToken = generateRefreshToken(userInfo);

        return TokenPayload.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private String generateAccessToken(UserInfo userInfo) {
        List<String> authorities = jwtHelper.getAuthorities(userInfo);

        return generateAccessToken(userInfo, Map.of(
                USER_ID_CLAIM.getClaim(), userInfo.id(),
                EMAIL_VERIFIED_CLAIM.getClaim(), userInfo.emailVerified(),
                ROLES_CLAIM.getClaim(), authorities,
                STATUS_CLAIM.getClaim(), userInfo.getStatus()
        ));
    }

    private String generateAccessToken(UserInfo userInfo, Map<String, Object> claims) {
        return buildToken(userInfo, claims, jwtProperties.getAccessExpirationTime());
    }

    private String generateRefreshToken(UserInfo userInfo) {
        return buildToken(userInfo, Map.of(), jwtProperties.getRefreshExpirationTime());
    }

    private String buildToken(UserInfo userInfo, Map<String, Object> claims, int expiration) {
        if (userInfo == null) {
            throw new IllegalArgumentException("User info is required.");
        }

        return Jwts.builder()
                .claims(claims)
                .subject(userInfo.email())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(jwtHelper.getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
