package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.domain.security.AuthUser;
import com.vendo.auth_service.adapter.out.security.common.type.UserAuthority;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public class AuthUserDataBuilder {

    public static AuthUser.AuthUserBuilder buildAuthUserWithAllFields() {
        return AuthUser.builder()
                .id(String.valueOf(UUID.randomUUID()))
                .email("test@gmail.com")
                .role(UserAuthority.USER)
                .status(UserStatus.INCOMPLETE)
                .birthDate(LocalDate.now())
                .fullName("Test Name")
                .providerType(ProviderType.LOCAL)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }
}
