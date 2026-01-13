package com.vendo.auth_service.domain.user.dto;

import com.vendo.auth_service.adapter.in.web.dto.UserProfileResponse;
import com.vendo.auth_service.adapter.out.security.common.type.UserAuthority;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;

import java.time.Instant;
import java.time.LocalDate;

public class UserProfileResponseBuilder {
    public static UserProfileResponse.UserProfileResponseBuilder buildUserProfileResponseWithAllFields() {
        return UserProfileResponse.builder()
                .id("1")
                .email("test@gmail.com")
                .role(UserAuthority.USER)
                .fullName("Test Name")
                .birthDate(LocalDate.of(2000, 1, 1))
                .providerType(ProviderType.LOCAL)
                .status(UserStatus.INCOMPLETE)
                .createdAt(Instant.now())
                .updatedAt(Instant.now());
    }
}
