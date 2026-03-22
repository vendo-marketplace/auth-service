package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.InternalJwtProperties;
import com.vendo.auth_service.adapter.security.out.jwt.utils.JwtUtils;
import com.vendo.core_lib.type.ServiceName;
import com.vendo.core_lib.type.ServiceRole;
import com.vendo.security_lib.type.InternalTokenClaim;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtInternalTokenService implements InternalTokenGenerationService {

    private final JwtUtils jwtUtils;

    private final InternalJwtProperties internalJwtProperties;

    @Override
    public String generateInternal() {
        Map<String, Object> claims = Map.of(
                InternalTokenClaim.ROLES.getClaim(), List.of(ServiceRole.INTERNAL.toString()),
                Claims.AUDIENCE, Set.of(ServiceName.USER_SERVICE.toString())
        );

        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(ServiceName.AUTH_SERVICE.toString())
                .claims(claims)
                .expiration(internalJwtProperties.getExpiration())
                .build();

        return jwtUtils.buildToken(internalJwtProperties.getKey(), jwtPayload);
    }

}
