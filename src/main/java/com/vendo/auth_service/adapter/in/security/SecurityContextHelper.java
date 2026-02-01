package com.vendo.auth_service.adapter.in.security;

import com.vendo.auth_service.domain.security.AuthUser;
import com.vendo.auth_service.port.security.UserAuthenticationService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityContextHelper implements UserAuthenticationService {

    @Override
    public AuthUser getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthUser authUser)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return authUser;
    }
}

