package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Set;

@Builder
public record UserResponse(

        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        Set<UserRole> roles,
        ProviderType providerType,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {
}
