package com.vendo.auth_service.domain.user.model;

import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserRole;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.domain.user.service.UserActivityView;
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
) implements UserActivityView {

    @Override
    public UserStatus getStatus() {
        return status;
    }

    @Override
    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public Boolean active() {
        return status == UserStatus.ACTIVE;
    }
}
