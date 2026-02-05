package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.domain.user.common.exception.UserNotFoundException;
import com.vendo.auth_service.port.user.UserQueryPort;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserQueryAdapter implements UserQueryPort {

    private final UserClient userClient;

    @Override
    public User getByEmail(String email) {
        try {
            return userClient.getByEmail(email);
        } catch (FeignException.NotFound e) {
            throw new UserNotFoundException("User not found.");
        }
    }

    @Override
    public boolean existsByEmail(String email) {
        return userClient.existsByEmail(email).exists();
    }

}
