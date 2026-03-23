package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.user_lib.exception.UserNotFoundException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserCommandAdapter implements UserCommandPort {

    private final UserClient userClient;

    @Override
    public User ensureExists(String email) {
        try {
            return getByEmail(email);
        } catch (UserNotFoundException e) {
            User user = User.builder()
                    .email(email)
                    .role(UserRole.USER)
                    .status(UserStatus.ACTIVE)
                    .providerType(ProviderType.LOCAL)
                    .build();

            return save(user);
        }
    }

    @Override
    public User save(User user) {
        return userClient.save(user);
    }

    @Override
    public void update(String id, UpdateUserRequest request) {
        userClient.update(id, request);
    }

    private User getByEmail(String email) {
        return userClient.getByEmail(email);
    }

}
