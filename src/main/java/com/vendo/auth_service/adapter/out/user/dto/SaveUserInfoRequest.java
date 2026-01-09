package com.vendo.auth_service.adapter.out.user.dto;

import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;

@Builder
public record SaveUserInfoRequest(
        String email,
        UserRole role,
        UserStatus status,
        ProviderType providerType,
        String password,
        Boolean emailVerified) {
}

