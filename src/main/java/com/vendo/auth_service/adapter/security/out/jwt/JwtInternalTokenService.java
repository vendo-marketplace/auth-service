package com.vendo.auth_service.adapter.security.out.jwt;

import com.vendo.auth_service.adapter.security.out.jwt.props.InternalJwtProperties;
import com.vendo.auth_service.adapter.security.out.jwt.utils.JwtUtils;
import com.vendo.common.type.Service;
import com.vendo.domain.user.common.type.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;

@Component
@RequiredArgsConstructor
public class JwtInternalTokenService implements InternalTokenGenerationService {

    private final JwtUtils jwtUtils;

    private final InternalJwtProperties internalJwtProperties;

    @Override
    public String generateInternal() {
        Map<String, Object> claims = Map.of(ROLES_CLAIM.getClaim(), List.of(UserRole.INTERNAL.name()));

        JwtUtils.JwtPayload jwtPayload = JwtUtils.JwtPayload.builder()
                .subject(Service.AUTH_SERVICE.getName())
                .claims(claims)
                .expiration(internalJwtProperties.getExpiration())
                .build();
        return jwtUtils.buildToken(internalJwtProperties.getKey(), jwtPayload);
    }

}
