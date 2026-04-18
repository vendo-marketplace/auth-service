package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.UserStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


@Component
public class UserSecurity {

    public void validateCompletion(Authentication authentication) {
        AuthUser user = (AuthUser) authentication.getPrincipal();

        if (user.status() == UserStatus.BLOCKED) {
            throw new UserBlockedException("User is blocked.");
        }
        if (!user.emailVerified()) {
            throw new UserEmailNotVerifiedException("User email is not verified.");
        }
    }
}
