package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.auth.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserSecurity {

    private final UserAuthenticationService authenticationService;

    public boolean hasAccess() {
        try {
            User authUser = authenticationService.getAuthUser();
            authUser.throwIfBlocked();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
