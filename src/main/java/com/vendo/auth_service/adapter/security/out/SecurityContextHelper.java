package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import com.vendo.auth_service.port.user.UserQueryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityContextHelper implements UserAuthenticationService {

    private final UserMapper userMapper;

    private final UserQueryPort userQueryPort;

    @Override
    public AuthUserResponse getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthUser authUser)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return userMapper.toResponse(authUser);
    }

    public AuthUser getAuthUser(String email) {
        User user = userQueryPort.getByEmail(email);
        return userMapper.toAuthUser(user);
    }

}

