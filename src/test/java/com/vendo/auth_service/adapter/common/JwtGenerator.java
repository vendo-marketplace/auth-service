package com.vendo.auth_service.adapter.common;

import com.vendo.auth_service.adapter.out.security.helper.JwtHelper;
import com.vendo.auth_service.adapter.common.config.JwtProperties;
import com.vendo.auth_service.domain.user.common.dto.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.vendo.security.common.type.TokenClaim.*;

@Service
@RequiredArgsConstructor
public class JwtGenerator {

    private final JwtHelper jwtHelper;

    private final JwtProperties jwtProperties;

    public String generateAccessToken(User user) {
        List<String> authorities = jwtHelper.getAuthorities(user);

        return generateAccessToken(user, Map.of(
                USER_ID_CLAIM.getClaim(), user.id(),
                EMAIL_VERIFIED_CLAIM.getClaim(), user.getEmailVerified(),
                ROLES_CLAIM.getClaim(), authorities,
                STATUS_CLAIM.getClaim(), user.getStatus()
        ));
    }

    private String generateAccessToken(User user, Map<String, Object> claims) {
        return buildToken(user, claims, jwtProperties.getAccessExpirationTime());
    }

    public String generateTokenWithExpiration(User user, int expiration) {
        List<String> authorities = jwtHelper.getAuthorities(user);
        return buildToken(user, Map.of(ROLES_CLAIM.getClaim(), authorities), expiration);
    }
    private String buildToken(User user, Map<String, Object> claims, int expiration) {
        if (user == null) {
            throw new IllegalArgumentException("User is required.");
        }

        return Jwts.builder()
                .claims(claims)
                .subject(user.email())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(jwtHelper.getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
