package com.vendo.auth_service.domain.user.model;

import com.vendo.user_lib.exception.*;
import com.vendo.user_lib.type.*;
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

    public void validateAccess() {
        if (Objects.isNull(status)|| Objects.isNull(emailVerified)) {
            throw new IllegalArgumentException("Status and email verification are required.");
        }

        throwIfBlocked();
        throwIfUnverified();
    }

    public void validateComplete() {
        if (Objects.nonNull(birthDate) && !StringUtils.isEmpty(fullName)) {
            throw new UserAlreadyCompletedException("User profile is already completed.");
        }
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
}
