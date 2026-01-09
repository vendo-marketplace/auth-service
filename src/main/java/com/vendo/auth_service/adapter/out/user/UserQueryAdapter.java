package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.adapter.out.user.dto.User;
import com.vendo.auth_service.adapter.out.user.exception.UserNotFoundException;
import com.vendo.auth_service.port.user.UserQueryPort;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class UserQueryAdapter implements UserQueryPort {

    private final UserClient userClient;

    @Override
    public Optional<User> findByEmail(String email) {
        try {
            return Optional.of(userClient.getByEmail(email));
        } catch (FeignException.NotFound e) {
            return Optional.empty();
        }
    }

    @Override
    public User getByEmail(String email) {
        try {
            return userClient.getByEmail(email);
        } catch (FeignException.NotFound e) {
            throw new UserNotFoundException("User info not found.");
        }
    }

}
