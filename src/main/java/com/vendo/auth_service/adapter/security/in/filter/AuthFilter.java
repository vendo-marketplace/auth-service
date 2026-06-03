package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.security_lib.type.UserHeaders;

import static com.vendo.core_lib.constants.Delimiters.COMMA_DELIMITER;

import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
import com.vendo.utils_lib.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {

    private final AuthAntPathResolver authAntPathResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext.getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        User user = extractUserFromHeaders(request);
        addAuthenticationToContext(user);
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return authAntPathResolver.isPermittedPath(requestURI);
    }

    private void addAuthenticationToContext(User user) {
        List<SimpleGrantedAuthority> authorities = user.roles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .toList();

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user,
                null,
                authorities);

        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private String getRequiredHeader(HttpServletRequest request, UserHeaders header) {
        String value = request.getHeader(header.getHeader());

        if (StringUtils.isEmpty(value)) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return value;
    }

    private User extractUserFromHeaders(HttpServletRequest request) {
        Set<UserRole> roles = Arrays.stream(getRequiredHeader(request, UserHeaders.ROLES)
                .split(COMMA_DELIMITER)).map(UserRole::valueOf).collect(Collectors.toSet());

        return User.builder()
                .id(getRequiredHeader(request, UserHeaders.USER_ID))
                .email(getRequiredHeader(request, UserHeaders.USER_EMAIL))
                .status(UserStatus.valueOf(getRequiredHeader(request, UserHeaders.STATUS)))
                .roles(roles)
                .emailVerified(Boolean.valueOf(getRequiredHeader(request, UserHeaders.EMAIL_VERIFIED)))
                .build();
    }

}
