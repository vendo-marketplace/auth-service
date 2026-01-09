package com.vendo.auth_service.adapter.out.user.dto;

import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record UpdateUserRequest(
        String fullName,
        LocalDate birthDate,
        Boolean emailVerified,
        UserStatus status,
        ProviderType providerType) {
}
