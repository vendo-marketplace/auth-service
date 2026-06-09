package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.core_lib.type.ServiceName;
import com.vendo.core_lib.type.ServiceRole;
import com.vendo.security_lib.type.TokenClaim;
import com.vendo.security_starter.jwt.JwtPayload;
import com.vendo.security_starter.jwt.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtInternalTokenAdapter implements InternalTokenGenerationPort {

    private final JwtProperties props;

    @Override
    public String generate() {
        JwtProperties.Internal internal = props.getInternal();

        Map<String, Object> claims = Map.of(
                TokenClaim.ROLES.getClaim(), List.of(ServiceRole.INTERNAL.toString()),
                Claims.AUDIENCE, Set.of(ServiceName.USER_SERVICE.toString())
        );

        JwtPayload jwtPayload = JwtPayload.builder()
                .subject(ServiceName.AUTH_SERVICE.toString())
                .claims(claims)
                .expiration(internal.expirationTime())
                .build();

        return JwtService.buildToken(jwtPayload, internal.key());
    }

}
