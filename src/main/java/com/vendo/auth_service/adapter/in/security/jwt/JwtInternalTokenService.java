package com.vendo.auth_service.adapter.in.security.jwt;

import com.vendo.auth_service.adapter.in.security.jwt.props.InternalJwtProperties;
import com.vendo.auth_service.domain.user.type.UserAuthority;
import com.vendo.common.type.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.vendo.security.common.type.TokenClaim.ROLES_CLAIM;

@Component
@RequiredArgsConstructor
public class JwtInternalTokenService implements InternalTokenGenerationService {

    private final InternalJwtProperties internalJwtProperties;

    @Override
    public String generateInternal() {
        Map<String, Object> claims = Map.of(ROLES_CLAIM.getClaim(), List.of(UserAuthority.INTERNAL.getAuthority()));
        return buildToken(Service.AUTH_SERVICE.getName(), claims, internalJwtProperties.getExpiration());
    }

    private String buildToken(String subject, Map<String, Object> claims, int expiration) {
        if (subject.isBlank()) {
            throw new IllegalArgumentException("Subject is required.");
        }

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(JwtTokenService.getSignInKey(internalJwtProperties.getKey()), SignatureAlgorithm.HS256)
                .compact();
    }
}
