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
        throwIfBlocked();
        throwIfNotVerified();
    }

    public void throwIfCompleted() {
        if (Objects.nonNull(birthDate) && !StringUtils.isEmpty(fullName)) {
            throw new UserAlreadyCompletedException("User is already completed.");
        }
    }

    public void throwIfNotVerified() {
        if (Objects.nonNull(emailVerified) && !emailVerified) {
            throw new UserEmailNotVerifiedException("User email is not verified.");
        }
    }

    public void throwIfBlocked() {
        if (Objects.nonNull(status) && status == UserStatus.BLOCKED) {
            throw new UserBlockedException("User is blocked.");
        }
    }
}
