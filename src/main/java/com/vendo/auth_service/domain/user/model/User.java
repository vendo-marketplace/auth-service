package com.vendo.auth_service.domain.user.model;

import com.vendo.auth_service.domain.user.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.StringUtils;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;

@Builder
public record User(

        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        UserRole role,
        ProviderType providerType,
        String password,
        LocalDate birthDate,
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {

    public void validateCompletion() {
        if (Objects.isNull(status)|| Objects.isNull(emailVerified)) {
            throw new IllegalArgumentException("Status and email verification are required.");
        }

        throwIfBlocked();
        throwIfUnverified();
        throwIfAlreadyCompleted();
    }

    private void throwIfUnverified() {
        if (!emailVerified) {
            throw new UserEmailNotVerifiedException("User email is not verified.");
        }
    }

    private void throwIfBlocked() {
        if (status == UserStatus.BLOCKED) {
            throw new UserBlockedException("User is blocked.");
        }
    }

    private void throwIfAlreadyCompleted() {
        if (Objects.nonNull(birthDate) && !StringUtils.isEmpty(fullName)) {
            throw new UserAlreadyCompletedException("User profile is already completed.");
        }
    }
}
