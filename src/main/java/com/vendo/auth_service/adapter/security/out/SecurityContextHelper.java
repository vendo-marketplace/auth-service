package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.domain.user.exception.UnauthorizedException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import com.vendo.auth_service.port.user.UserQueryPort;
import lombok.RequiredArgsConstructor;
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

        if (authentication == null || !(authentication.getPrincipal() instanceof User user)) {
            throw new UnauthorizedException("Unauthorized.");
        }

        return userMapper.toResponse(user);
    }

    @Override
    public User getUser(String email) {
        return userQueryPort.getByEmail(email);
    }

}

