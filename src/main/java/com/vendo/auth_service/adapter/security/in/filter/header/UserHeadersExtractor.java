package com.vendo.auth_service.adapter.security.in.filter.header;

import com.vendo.auth_service.domain.user.model.User;

import static com.vendo.security_lib.type.UserHeaders.*;

import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static com.vendo.core_lib.constants.Delimiters.COMMA_DELIMITER;

@Slf4j
@Component
public class UserHeadersExtractor {

    public User extract(HttpServletRequest request) {
        return User.builder()
                .id(required(request, ID.getHeader()))
                .email(required(request, EMAIL.getHeader()))
                .status(extractStatus(request.getHeader(STATUS.getHeader())))
                .roles(extractRoles(request.getHeader(ROLES.getHeader())))
                .emailVerified(Boolean.valueOf(required(request, EMAIL_VERIFIED.getHeader())))
                .build();
    }

    private String required(HttpServletRequest request, String header) {
        String value = request.getHeader(header);
        if (StringUtils.isEmpty(value)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return value;
    }

    private UserStatus extractStatus(String status) {
        try {
            return UserStatus.valueOf(status);
        } catch (IllegalArgumentException | NullPointerException e) {
            log.error("Invalid status header: {}.", status);
            throw new BadCredentialsException("Invalid user context.");
        }
    }

    private Set<UserRole> extractRoles(String roles) {
        if (StringUtils.isEmpty(roles)) return Set.of();
        return Arrays.stream(roles.split(COMMA_DELIMITER))
                .map(UserRole::valueOf).collect(Collectors.toSet());
    }

}
