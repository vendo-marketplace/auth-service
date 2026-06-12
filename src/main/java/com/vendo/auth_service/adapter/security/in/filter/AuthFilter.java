package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.security_lib.type.AuthHeader;
import com.vendo.security_starter.filter.header.HeaderExtractor;
import com.vendo.security_starter.filter.header.UserHeaderExtractor;
import com.vendo.security_starter.filter.utils.FilterUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
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

        try {
            User user = parseUserFrom(request);
            FilterUtils.addAuthToContext(user, user.toRoleNames());
        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            throw e;
        } catch (Exception e) {
            log.info(e.getMessage());
            SecurityContextHolder.clearContext();
            throw new AuthenticationServiceException("Internal authentication error.");
        }

        filterChain.doFilter(request, response);
    }

    private User parseUserFrom(HttpServletRequest request) {
        String id = headerExtractor.require(AuthHeader.ID.getHeader(), request);
        String email = request.getHeader(AuthHeader.EMAIL.getHeader());
        String emailVerified = request.getHeader(AuthHeader.EMAIL_VERIFIED.getHeader());

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
