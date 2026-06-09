package com.vendo.auth_service.domain.user.model;

import com.vendo.user_lib.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.StringUtils;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

@Builder
public record User(

        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        List<UserRole> roles,
        ProviderType providerType,
        String password,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {

    public void throwIfCompleted() {
        if (Objects.nonNull(birthDate) && !StringUtils.isEmpty(fullName)) {
            throw new UserAlreadyCompletedException("User has already completed.");
        }
    }
}
