package com.vendo.auth_service.adapter.security.out.jwt.parser;

import com.vendo.auth_service.port.security.BearerTokenExtractor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;

@Component
public class JwtTokenExtractor implements BearerTokenExtractor {

    @Override
    public String extract(String token) {
        if (!token.startsWith(BEARER_PREFIX)) {
            throw new BadCredentialsException("Invalid or expired token.");
        }

        return token.substring(BEARER_PREFIX.length());
    }

}
