package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.port.user.UserLookupPort;
import com.vendo.user_lib.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserLookupAdapter implements UserLookupPort {

    private final UserClient client;

    @Override
    public void requireExistence(String email) {
        if (!client.existsByEmail(email).exists()) {
            throw new UserNotFoundException("User not found.");
        }
    }
}
