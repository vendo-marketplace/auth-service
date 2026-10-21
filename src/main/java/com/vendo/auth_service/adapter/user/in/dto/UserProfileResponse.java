package com.vendo.auth_service.adapter.user.in.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.util.Set;

@Builder(toBuilder = true)
public record UserProfileResponse(

        String id,
        String email,
        Set<UserRole> roles,
        UserStatus status,
        ProviderType providerType,
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {
}
