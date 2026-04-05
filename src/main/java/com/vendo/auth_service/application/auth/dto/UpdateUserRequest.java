package com.vendo.auth_service.application.auth.dto;

import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record UpdateUserRequest(
        String fullName,
        String password,
        LocalDate birthDate,
        UserStatus status,
        Boolean emailVerified,
        ProviderType providerType
) {
}
