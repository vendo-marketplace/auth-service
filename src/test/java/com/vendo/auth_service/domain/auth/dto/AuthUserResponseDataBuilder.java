package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.application.auth.dto.UserResponse;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public class AuthUserResponseDataBuilder {

    public static UserResponse.UserResponseBuilder buildWithAllFields() {
        return UserResponse.builder()
                .id(String.valueOf(UUID.randomUUID()))
                .email("test@gmail.com")
                .role(UserRole.USER)
                .status(UserStatus.INCOMPLETE)
                .birthDate(LocalDate.now())
                .fullName("Test Name")
                .providerType(ProviderType.LOCAL)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }

}
