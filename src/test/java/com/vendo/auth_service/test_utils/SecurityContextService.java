package com.vendo.auth_service.test_utils;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.security_lib.type.AuthHeader;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static com.vendo.core_lib.constants.Delimiters.COMMA_DELIMITER;

public class SecurityContextService {

    public static SecurityContext initializeSecurityContext(User user) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        List<SimpleGrantedAuthority> authorities = user.roles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .toList();

        securityContext.setAuthentication(new UsernamePasswordAuthenticationToken(
                user,
                null,
                authorities)
        );

        return securityContext;
    }

    public static SecurityContext initializeSecurityContext(AbstractAuthenticationToken authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);

        return securityContext;
    }

    public static HttpHeaders extractHeaders(User user) {
        HttpHeaders httpHeaders = new HttpHeaders();

        httpHeaders.add(AuthHeader.ID.getHeader(), user.id());
        httpHeaders.add(AuthHeader.EMAIL.getHeader(), user.email());
        httpHeaders.add(AuthHeader.ROLES.getHeader(), String.join(COMMA_DELIMITER, user.toRoleNames()));
        httpHeaders.add(AuthHeader.EMAIL_VERIFIED.getHeader(), String.valueOf(user.emailVerified()));
        httpHeaders.add(AuthHeader.STATUS.getHeader(), String.valueOf(user.status()));

        return httpHeaders;
    }

}
