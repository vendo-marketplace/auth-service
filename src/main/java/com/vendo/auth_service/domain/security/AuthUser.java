package com.vendo.auth_service.domain.security;

import com.vendo.auth_service.adapter.out.security.common.type.UserAuthority;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;

@Builder
public record AuthUser(
        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        UserAuthority role,
        ProviderType providerType,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt
) {
}
