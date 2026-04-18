package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;

import java.time.Instant;
import java.time.LocalDate;

public class AuthUserResponseDataBuilder {

    public static AuthUserResponse.AuthUserResponseBuilder buildWithAllFields() {
        return AuthUserResponse.builder()
                .id("id")
                .email("test@gmail.com")
                .role(UserRole.USER)
                .status(UserStatus.ACTIVE)
                .birthDate(LocalDate.of(2000, 1, 1))
                .fullName("Test Name")
                .providerType(ProviderType.LOCAL)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }

}
