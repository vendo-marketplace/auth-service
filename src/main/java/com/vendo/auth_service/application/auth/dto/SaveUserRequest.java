package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

@Builder
public record SaveUserRequest(
        String email,
        String password,
        UserRole role,
        UserStatus status,
        ProviderType providerType
) {
}
