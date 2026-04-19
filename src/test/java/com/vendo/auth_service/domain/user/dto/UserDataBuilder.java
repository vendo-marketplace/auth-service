package com.vendo.auth_service.domain.user.dto;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public class UserDataBuilder {

    public static User.UserBuilder withAllFields() {
        return User.builder()
                .id("id")
                .email("test@gmail.com")
                .password("Qwerty1234@")
                .role(UserRole.USER)
                .fullName("Test Name")
                .birthDate(LocalDate.of(2000, 1, 1))
                .providerType(ProviderType.LOCAL)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }

    public static User.UserBuilder withUserRole() {
        return User.builder()
                .role(UserRole.USER);
    }
}
