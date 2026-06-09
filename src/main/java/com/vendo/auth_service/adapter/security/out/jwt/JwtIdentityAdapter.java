package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.port.security.TokenIdentityPort;
import com.vendo.core_lib.utils.StringUtils;
import com.vendo.security_lib.http.HttpUtils;
import com.vendo.security_lib.type.TokenClaim;
import com.vendo.security_starter.jwt.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtIdentityAdapter implements TokenIdentityPort {

    private final JwtProperties jwtProperties;

    @Override
    public String extractId(String authorization) {
        String token = HttpUtils.getTokenFrom(authorization);
        Claims claims = JwtService.extractAll(token, jwtProperties.getSecret().key());
        return parseId(claims);
    }

    private String parseId(Claims claims) {
        String id = claims.get(TokenClaim.ID.getClaim(), String.class);

        if (StringUtils.isEmpty(id)) {
            throw new IllegalArgumentException("Id is required.");
        }

        return id;
    }
}
