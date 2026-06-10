package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.application.auth.dto.SaveUserRequest;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserCommandAdapter implements UserCommandPort {

    private final UserClient userClient;

    @Override
    public User save(SaveUserRequest request) {
        return userClient.save(request);
    }

    @Override
    public void update(String id, UpdateUserRequest request) {
        userClient.update(id, request);
    }

}
