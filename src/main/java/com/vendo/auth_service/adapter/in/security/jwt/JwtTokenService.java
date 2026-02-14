package com.vendo.auth_service.adapter.in.security.jwt;

import com.vendo.auth_service.adapter.in.security.jwt.props.JwtProperties;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.domain.auth.dto.TokenPayload;
import com.vendo.auth_service.port.security.TokenGenerationService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.vendo.security.common.type.TokenClaim.*;

@Component
@RequiredArgsConstructor
public class JwtTokenService implements TokenGenerationService {

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

    public static Claims extractAllClaims(String token, String secretKey) {
        return parseSignedClaims(token, secretKey).getPayload();
    }

    public static List<String> getAuthorities(User user) {
        return Stream.of(user.role())
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    public static Key getSignInKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    private String generateAccessToken(User user) {
        List<String> authorities = getAuthorities(user);
        Map<String, Object> claims = Map.of(
                USER_ID_CLAIM.getClaim(), user.id(),
                EMAIL_VERIFIED_CLAIM.getClaim(), user.emailVerified(),
                ROLES_CLAIM.getClaim(), authorities,
                STATUS_CLAIM.getClaim(), user.getStatus()
        );

        return buildToken(user.email(), claims, jwtProperties.getAccessExpiration());
    }

    private String generateRefreshToken(String subject) {
        return buildToken(subject, Map.of(), jwtProperties.getRefreshExpiration());
    }

    private String buildToken(String subject, Map<String, Object> claims, int expiration) {
        if (subject.isBlank()) {
            throw new IllegalArgumentException("Subject is required.");
        }

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(jwtProperties.getKey()), SignatureAlgorithm.HS256)
                .compact();
    }

    private static Jws<Claims> parseSignedClaims(String token, String secretKey) throws JwtException {
        return Jwts.parser()
                .verifyWith((SecretKey) getSignInKey(secretKey))
                .build()
                .parseSignedClaims(token);
    }
}
