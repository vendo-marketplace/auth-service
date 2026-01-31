package com.vendo.auth_service.adapter.in.security;

import com.vendo.auth_service.adapter.in.security.dto.AuthUser;
import com.vendo.auth_service.adapter.out.user.common.mapper.UserMapper;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.adapter.out.security.helper.JwtHelper;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.domain.user.service.UserActivityPolicy;
import com.vendo.security.common.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Collections;

import static com.vendo.security.common.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtHelper jwtHelper;

    private final AuthAntPathResolver authAntPathResolver;

    private final UserQueryPort userQueryPort;

    private final UserMapper userMapper;

    @Qualifier("handlerExceptionResolver")
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext.getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwtToken = getTokenFromRequest(request);
            Claims claims = jwtHelper.extractAllClaims(jwtToken);

            AuthUser authUser = validateUserAccessibility(claims);
            addAuthenticationToContext(authUser);
        } catch (Exception e) {
            handlerExceptionResolver.resolveException(request, response, null, e);
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return authAntPathResolver.isPermittedPath(requestURI);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);

        if (authorization == null) {
            throw new AuthenticationCredentialsNotFoundException("Unauthorized.");
        } else if (!authorization.startsWith(BEARER_PREFIX)) {
            throw new InvalidTokenException("Invalid token.");
        }

        return authorization.substring(BEARER_PREFIX.length());
    }

    private AuthUser validateUserAccessibility(Claims claims) {
        User user = userQueryPort.getByEmail(claims.getSubject());
        UserActivityPolicy.validateActivity(user);
        return userMapper.toAuthUserFromUser(user);
    }

    private void addAuthenticationToContext(AuthUser authUser) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                authUser,
                null,
                Collections.singleton(authUser.role()));

        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
