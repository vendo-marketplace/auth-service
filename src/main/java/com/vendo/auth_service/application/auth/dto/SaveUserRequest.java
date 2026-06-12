package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.util.Set;

@Builder
public record SaveUserRequest(
        String email,
        String fullName,
        String password,
        Set<UserRole> roles,
        UserStatus status,
        ProviderType providerType
) {
}
