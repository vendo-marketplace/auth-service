package com.vendo.auth_service.adapter.out.user;

import com.vendo.auth_service.adapter.out.user.dto.SaveUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.User;
import com.vendo.auth_service.adapter.out.user.exception.UserNotFoundException;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserCommandQuery implements UserCommandPort {

    private final UserClient userClient;

    @Override
    public User ensureExists(String email) {
        try {
            return getByEmail(email);
        } catch (FeignException.NotFound e) {

            SaveUserRequest saveUserRequest = SaveUserRequest.builder()
                    .email(email)
                    .role(UserRole.USER)
                    .status(UserStatus.ACTIVE)
                    .providerType(ProviderType.LOCAL)
                    .build();

            return save(saveUserRequest);
        }
    }

    @Override
    public User save(SaveUserRequest saveUserRequest) {
        return userClient.save(SaveUserRequest.builder()
                .email(saveUserRequest.email())
                .role(saveUserRequest.role())
                .status(saveUserRequest.status())
                .providerType(saveUserRequest.providerType())
                .build());
    }

    @Override
    public void update(String id, UpdateUserRequest updateUserRequest) {
    }

    private User getByEmail(String email) {
        try {
            return userClient.getByEmail(email);
        } catch (FeignException.NotFound e) {
            throw new UserNotFoundException("User not found.");
        }
    }
}
