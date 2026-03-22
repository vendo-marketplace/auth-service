package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityContextHelper implements UserAuthenticationService {

    private final UserMapper userMapper;

    @Override
    public AuthUserResponse getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthUser authUser)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return userMapper.toResponse(authUser);
    }

}

