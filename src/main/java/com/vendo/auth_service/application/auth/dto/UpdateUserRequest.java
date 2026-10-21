package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

@Builder
public record UpdateUserRequest(
        String fullName,
        String password,
        UserStatus status,
        Boolean emailVerified,
        ProviderType providerType
) {
}
