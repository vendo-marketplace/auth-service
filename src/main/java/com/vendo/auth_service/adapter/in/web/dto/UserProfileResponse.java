package com.vendo.auth_service.adapter.in.web.dto;

import com.vendo.auth_service.adapter.out.security.common.type.UserAuthority;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;

@Builder(toBuilder = true)
public record UserProfileResponse(
        String id,
        String email,
        UserAuthority role,
        UserStatus status,
        ProviderType providerType,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt) {
}
