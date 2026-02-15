package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class SecurityContextHelper implements UserAuthenticationService {

    @Override
    public AuthUserResponse getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthUserResponse authUserResponse)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return authUserResponse;
    }
}

