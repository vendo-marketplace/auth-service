package com.vendo.auth_service.domain.user.common.dto;

import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;
import lombok.With;

@Builder
public record SaveUserRequest(
        @With
        String email,
        UserRole role,
        UserStatus status,
        ProviderType providerType,
        String password,
        Boolean emailVerified) {
}

