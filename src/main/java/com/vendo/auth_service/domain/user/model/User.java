package com.vendo.auth_service.domain.user.model;

import com.vendo.user_lib.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.StringUtils;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;
import java.util.Set;

@Builder
public record User(

        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        Set<UserRole> roles,
        ProviderType providerType,
        String password,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {

    public void validateComplete() {
        if (Objects.nonNull(birthDate) && !StringUtils.isEmpty(fullName)) {
            throw new UserAlreadyCompletedException("User profile is already completed.");
        }
    }
}
