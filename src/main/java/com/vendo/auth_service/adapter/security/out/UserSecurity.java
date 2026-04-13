package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.type.UserRole;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class UserSecurity {

    public void validateAuthCompleted(Authentication auth) {
        User user = (User) auth.getPrincipal();
        Objects.requireNonNull(user).validateActivity();
    }

    public void validateAuthCompletedAdmin(Authentication auth) {
        User user = (User) auth.getPrincipal();

        if (Objects.requireNonNull(user).role() != UserRole.ADMIN)
            throw new AccessDeniedException("Resource is unreachable.");

        validateAuthCompleted(auth);
    }

}
