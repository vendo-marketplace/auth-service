package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.domain.user.exception.UnauthorizedException;
import com.vendo.auth_service.port.security.TokenIdentityPort;
import com.vendo.core_lib.utils.StringUtils;
import com.vendo.security_lib.type.TokenClaim;
import com.vendo.security_starter.jwt.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenIdentityAdapter implements TokenIdentityPort {

    private final JwtProperties jwtProperties;

    @Override
    public String extractId(String token) {
        try {
            Claims claims = JwtService.extractAll(token, jwtProperties.getSecret().key());
            return parseId(claims);
        } catch (JwtException e) {
            log.warn("Token parsing failed: {}", e.getMessage());
            throw new UnauthorizedException("Invalid or expired refresh token.");
        }
    }

    private String parseId(Claims claims) {
        String id = claims.get(TokenClaim.ID.getClaim(), String.class);

        if (StringUtils.isEmpty(id)) {
            throw new UnauthorizedException("Invalid or expired token.");
        }

        return id;
    }
}
