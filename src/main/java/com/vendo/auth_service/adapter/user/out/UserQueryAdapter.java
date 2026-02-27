package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserQueryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserQueryAdapter implements UserQueryPort {

    private final UserClient userClient;

    @Override
    public User getByEmail(String email) {
        return userClient.getByEmail(email);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userClient.existsByEmail(email).exists();
    }

}
