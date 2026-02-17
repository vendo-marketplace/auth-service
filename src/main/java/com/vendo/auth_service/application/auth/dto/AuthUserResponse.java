package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;

@Builder
public record AuthUserResponse(
        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        UserRole role,
        ProviderType providerType,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt
) {
}
