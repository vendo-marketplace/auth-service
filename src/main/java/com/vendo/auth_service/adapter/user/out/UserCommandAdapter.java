package com.vendo.auth_service.adapter.user.out;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.domain.user.exception.UserNotFoundException;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import feign.FeignException;
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
        } catch (FeignException.NotFound e) {
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
    public void update(String id, User user) {
        userClient.update(id, user);
    }

    private User getByEmail(String email) {
        try {
            return userClient.getByEmail(email);
        } catch (FeignException.NotFound e) {
            throw new UserNotFoundException("User not found.");
        }
    }

}
