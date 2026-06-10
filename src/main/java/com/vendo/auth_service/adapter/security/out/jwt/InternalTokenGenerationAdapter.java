package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.JwtProperties;
import com.vendo.core_lib.type.ServiceName;
import com.vendo.core_lib.type.ServiceRole;
import com.vendo.security_lib.type.TokenClaim;
import com.vendo.security_starter.jwt.JwtPayload;
import com.vendo.security_starter.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class InternalTokenGenerationAdapter implements InternalTokenGenerationPort {

    private final JwtProperties props;

    @Override
    public String generate() {
        JwtProperties.Internal internal = props.getInternal();

        JwtPayload jwtPayload = JwtPayload.builder()
                .subject(ServiceName.AUTH_SERVICE.toString())
                .audience(Set.of(ServiceName.USER_SERVICE.toString()))
                .claims(Map.of(TokenClaim.ROLES.getClaim(), ServiceRole.INTERNAL.toString()))
                .expiration(internal.expirationTime())
                .build();

        return JwtService.buildToken(jwtPayload, internal.key());
    }

}
