package com.vendo.auth_service.adapter.security.out.jwt.parser;

import com.vendo.auth_service.adapter.security.out.jwt.JwtTokenService;
import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtClaimsParser implements TokenClaimsParser {

    private final JwtProperties jwtProperties;

    private final JwtTokenService jwtTokenService;

    @Override
    public String extractSubject(String token) {
        return jwtTokenService.extractAllClaims(token, jwtProperties.getKey()).getSubject();
    }

}
