package com.vendo.auth_service.adapter.security.out.jwt.parser;

import com.vendo.auth_service.adapter.security.out.jwt.JwtService;
import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.auth_service.port.security.BearerTokenExtractor;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import static com.vendo.security_lib.http.HttpUtils.BEARER_PREFIX;

@Component
@RequiredArgsConstructor
public class JwtClaimsParser implements TokenClaimsParser {

    private final JwtProperties jwtProperties;
    private final JwtService jwtService;

    private final BearerTokenExtractor bearerTokenExtractor;

    @Override
    public String extractSubject(String token) {
        String withoutBearer = token;

        if (token.startsWith(BEARER_PREFIX)) {
            withoutBearer = bearerTokenExtractor.extract(token);
        }

        return jwtService.extractAllClaims(withoutBearer, jwtProperties.getKey()).getSubject();
    }

}
