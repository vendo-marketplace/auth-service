package com.vendo.auth_service.adapter.security.out.jwt.utils;

import com.vendo.utils_lib.StringUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
public final class JwtUtils {

    public SecretKey getSignInKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public Jws<Claims> parseSignedClaims(String token, String secretKey) throws JwtException {
        return Jwts.parser()
                .verifyWith(getSignInKey(secretKey))
                .build()
                .parseSignedClaims(token);
    }

    public String buildToken(String secretKey, JwtPayload payload) {
        if (payload == null || StringUtils.isEmpty(payload.subject()))
            throw new IllegalArgumentException("Invalid payload.");

        return Jwts.builder()
                .subject(payload.subject())
                .claims(payload.claims())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + payload.expirationTime()))
                .signWith(getSignInKey(secretKey), Jwts.SIG.HS256)
                .compact();
    }

    @Builder
    public record JwtPayload(
            String subject,
            Map<String, Object> claims,
            long expirationTime) {
    }
}