package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.security_lib.type.UserHeader;
import com.vendo.security_starter.filter.header.HeaderExtractor;
import com.vendo.security_starter.filter.header.UserHeaderExtractor;
import com.vendo.security_starter.filter.utils.FilterUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {

    private final AuthAntPathResolver authAntPathResolver;

    private final UserHeaderExtractor userHeaderExtractor;
    private final HeaderExtractor headerExtractor;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext.getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        User user = parseUserFrom(request);
        FilterUtils.addAuthToContext(user, user.toRoleNames());

        filterChain.doFilter(request, response);
    }

    private User parseUserFrom(HttpServletRequest request) {
        String id = headerExtractor.require(UserHeader.ID.getHeader(), request);
        String email = headerExtractor.require(UserHeader.EMAIL.getHeader(), request);
        String emailVerified = headerExtractor.require(UserHeader.EMAIL_VERIFIED.getHeader(), request);

        return User.builder()
                .id(id)
                .email(email)
                .status(userHeaderExtractor.extractStatus(request))
                .roles(userHeaderExtractor.extractRoles(request))
                .emailVerified(Boolean.getBoolean(emailVerified))
                .build();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return authAntPathResolver.isPermittedPath(requestURI);
    }
}
