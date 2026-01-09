package com.vendo.auth_service.adapter.out.user.dto;

import com.vendo.auth_service.adapter.out.security.common.type.UserAuthority;
import com.vendo.domain.user.common.type.ProviderType;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.domain.user.service.UserActivityView;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Collections;

public record UserInfo(
        String id,
        String email,
        Boolean emailVerified,
        UserStatus status,
        UserAuthority role,
        ProviderType providerType,
        String password,
        LocalDate birthDate,
        String fullName
) implements UserActivityView {

    @Override
    public UserStatus getStatus() {
        return status;
    }

    @Override
    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(role);
    }

}
