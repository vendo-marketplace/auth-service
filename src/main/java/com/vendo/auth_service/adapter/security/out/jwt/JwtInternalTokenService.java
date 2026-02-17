package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.InternalJwtProperties;
import com.vendo.auth_service.adapter.security.out.jwt.utils.JwtUtils;
import com.vendo.core_lib.type.ServiceName;
import com.vendo.security_lib.type.TokenClaim;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtInternalTokenService implements InternalTokenGenerationService {

    private final JwtUtils jwtUtils;

    private final InternalJwtProperties internalJwtProperties;

    @Override
    public String generateInternal() {
        Map<String, Object> claims = Map.of(
                // TODO move to lib
                TokenClaim.ROLES.getClaim(), List.of("INTERNAL"),
                Claims.AUDIENCE, ServiceName.USER_SERVICE.getServiceName()
        );

        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(ServiceName.AUTH_SERVICE.getServiceName())
                .claims(claims)
                .expiration(internalJwtProperties.getExpiration())
                .build();

        return jwtUtils.buildToken(internalJwtProperties.getKey(), jwtPayload);
    }

}
