package com.vendo.auth_service.adapter.common;

import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.user_lib.type.UserRole;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

public class SecurityContextService {

    public static SecurityContext initializeSecurityContext(UserRole role) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(new UsernamePasswordAuthenticationToken(
                AuthUser.builder().build(),
                null,
                Collections.singletonList(new SimpleGrantedAuthority(role.name()))
        ));

        return securityContext;
    }

    public static SecurityContext initializeSecurityContext(AbstractAuthenticationToken authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);

        return securityContext;
    }

}
