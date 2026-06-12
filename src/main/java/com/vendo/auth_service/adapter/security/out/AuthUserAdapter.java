package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.AuthUserPort;
import com.vendo.security_starter.context.SecurityContextHelper;
import org.springframework.stereotype.Component;

@Component
public class AuthUserAdapter implements AuthUserPort {

    @Override
    public User getAuthUser() {
        return SecurityContextHelper.getAuthFromContext(User.class);
    }
}
