package com.vendo.auth_service.domain.user.dto;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;

import java.time.Instant;
import java.util.Set;

public class UserDataBuilder {

    public static User.UserBuilder withAllFields() {
        return User.builder()
                .id("id")
                .email("test@gmail.com")
                .password("Qwerty1234@")
                .roles(Set.of(UserRole.USER))
                .fullName(null)
                .birthDate(null)
                .providerType(ProviderType.LOCAL)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }

    public static User.UserBuilder withUserRole() {
        return User.builder()
                .roles(Set.of(UserRole.USER));
    }
}
