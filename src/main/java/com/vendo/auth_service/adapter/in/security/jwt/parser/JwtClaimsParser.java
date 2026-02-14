package com.vendo.auth_service.adapter.in.security.jwt.parser;

import com.vendo.auth_service.adapter.in.security.jwt.JwtTokenService;
import com.vendo.auth_service.adapter.in.security.jwt.props.JwtProperties;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtClaimsParser implements TokenClaimsParser {

    private final JwtProperties jwtProperties;

    @Override
    public String extractSubject(String token) {
        return JwtTokenService.extractAllClaims(token, jwtProperties.getKey()).getSubject();
    }

}
