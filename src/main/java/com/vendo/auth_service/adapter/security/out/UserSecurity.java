package com.vendo.auth_service.adapter.security.out;

import com.vendo.auth_service.domain.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserSecurity {

    private final SecurityContextHelper contextHelper;

    public void validateCompletion() {
        User authUser = contextHelper.getAuthUser();
        authUser.validateCompletion();
    }
}
