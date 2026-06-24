package com.vendo.auth_service.domain.user.model;

import com.vendo.auth_service.domain.user.exception.UserAlreadyVerifiedException;
import com.vendo.user_lib.exception.UserAlreadyCompletedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.core_lib.utils.StringUtils;
import lombok.Builder;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Builder
public record User(

        String id,
        String email,
        boolean emailVerified,
        UserStatus status,
        Set<UserRole> roles,
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

    public void throwIfVerified() {
        if (emailVerified) {
            throw new UserAlreadyVerifiedException("User email is already verified.");
        }
    }

    public Set<String> toRoleNames() {
        return roles.stream()
                .map(Enum::name)
                .collect(Collectors.toSet());
    }
}
