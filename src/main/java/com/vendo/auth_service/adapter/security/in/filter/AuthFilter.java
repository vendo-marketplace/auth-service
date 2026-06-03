package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.security_lib.type.UserHeaders;
import com.vendo.user_lib.type.UserRole;
import com.vendo.user_lib.type.UserStatus;
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
import java.util.Collections;

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
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user,
                null,
                Collections.singleton(new SimpleGrantedAuthority(user.role().name())));

        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private String getRequiredHeader(HttpServletRequest request, UserHeaders header) {
        String value = request.getHeader(header.getHeader());

        if (value == null || value.isBlank()) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        }

        return value;
    }

    private User extractUserFromHeaders(HttpServletRequest request) {
        return User.builder()
                .id(getRequiredHeader(request, UserHeaders.USER_ID))
                .email(getRequiredHeader(request, UserHeaders.USER_EMAIL))
                .status(UserStatus.valueOf(getRequiredHeader(request, UserHeaders.STATUS)))
                .role(UserRole.valueOf(getRequiredHeader(request, UserHeaders.ROLES)))
                .build();
    }

}
