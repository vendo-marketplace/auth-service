package com.vendo.auth_service.domain.user.model;

import com.vendo.user_lib.exception.UserBlockedException;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;

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
        if (status == null || emailVerified == null) {
            throw new IllegalArgumentException("Status and email verification are required.");
        }

        throwIfBlocked();
        throwIfUnverified();
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
