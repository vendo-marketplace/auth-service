package com.vendo.auth_service.adapter.out.security.helper;

import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.adapter.common.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class JwtHelper {

    private final JwtProperties jwtProperties;

    public List<String> getAuthorities(User user) {
        return Stream.of(user.role())
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    public Claims extractAllClaims(String token) {
        return parseSignedClaims(token).getPayload();
    }

    public Key getSignInKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    private Jws<Claims> parseSignedClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith((SecretKey) getSignInKey())
                .build()
                .parseSignedClaims(token);
    }
}