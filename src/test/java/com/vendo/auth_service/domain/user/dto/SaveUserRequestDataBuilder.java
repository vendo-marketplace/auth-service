package com.vendo.auth_service.domain.user.dto;

import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;

import java.util.UUID;

public class SaveUserRequestDataBuilder {

    public static SaveUserRequest.SaveUserRequestBuilder buildWithAllFields() {
        return SaveUserRequest.builder()
                .email("test@gmail.com")
                .role(UserRole.USER)
                .status(UserStatus.ACTIVE)
                .providerType(ProviderType.LOCAL)
                .password(String.valueOf(UUID.randomUUID()))
                .emailVerified(true);
    }

}
