package com.vendo.auth_service.adapter.security.out.jwt.parser;

import com.vendo.auth_service.domain.security.exception.InvalidCredentialsException;
import com.vendo.auth_service.port.auth.BearerTokenExtractor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;

@Slf4j
@Component
public class JwtTokenExtractor implements BearerTokenExtractor {

    @Override
    public String extract(String token) {
        if (!token.startsWith(BEARER_PREFIX)) {
            log.error("Token without bearer prefix.");
            throw new InvalidCredentialsException("Invalid token.");
        }

        return token.substring(BEARER_PREFIX.length());
    }

}
