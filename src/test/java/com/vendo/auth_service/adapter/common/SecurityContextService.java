package com.vendo.auth_service.adapter.common;

import com.vendo.auth_service.domain.security.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

public class SecurityContextService {

    public static SecurityContext initializeSecurityContext(AuthUser authUser) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(new UsernamePasswordAuthenticationToken(
                authUser,
                null,
                Collections.singletonList(authUser.role())
        ));

        return securityContext;
    }

    public static SecurityContext initializeSecurityContext(AbstractAuthenticationToken authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);

        return securityContext;
    }

}
