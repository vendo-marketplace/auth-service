package com.vendo.auth_service.http.user.dto;

import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import lombok.Builder;

import java.time.LocalDate;

@Builder
public record UpdateUserInfoRequest (
        String fullName,
        LocalDate birthDate,
        UserStatus status,
        ProviderType providerType) {
}
