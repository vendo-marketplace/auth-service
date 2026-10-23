package com.vendo.auth_service.domain.user.model;

import com.vendo.auth_service.domain.user.exception.UserAlreadyCompletedException;
import com.vendo.auth_service.domain.user.exception.UserAlreadyVerifiedException;
import com.vendo.auth_service.domain.user.pattern.UserRegexPatterns;
import com.vendo.user_lib.exception.UserEmailNotVerifiedException;
import com.vendo.user_lib.type.ProviderType;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.core_lib.utils.StringUtils;
import lombok.Builder;

import java.time.Instant;
import java.util.Set;
import java.util.regex.Pattern;
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
        String fullName,
        Instant createdAt,
        Instant updatedAt

) {

    private static final Pattern FULL_NAME_PATTERN = Pattern.compile(UserRegexPatterns.FULL_NAME);

    public static boolean isValidFullName(String fullName) {
        return !StringUtils.isEmpty(fullName) && FULL_NAME_PATTERN.matcher(fullName).matches();
    }

    public boolean isCompleted() {
        return !StringUtils.isEmpty(fullName);
    }

    public User withFullName(String fullName) {
        return new User(id, email, emailVerified, status, roles, providerType, password, fullName, createdAt, updatedAt);
    }

    public void throwIfEmailNotVerified() {
        if (!emailVerified) {
            throw new UserEmailNotVerifiedException("User email is not verified.");
        }
    }

    public void throwIfCompleted() {
        if (isCompleted()) {
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
