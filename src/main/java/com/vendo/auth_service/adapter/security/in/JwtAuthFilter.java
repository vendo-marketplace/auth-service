package com.vendo.auth_service.adapter.security.in;

import com.vendo.auth_service.adapter.user.out.mapper.UserMapper;
import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.TokenClaimsParser;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.security_lib.exception.InvalidTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Collections;

import static com.vendo.security_lib.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security_lib.constants.AuthConstants.BEARER_PREFIX;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthAntPathResolver authAntPathResolver;

    private final UserQueryPort userQueryPort;

    private final UserMapper userMapper;

    private final TokenClaimsParser tokenClaimsParser;

    @Qualifier("handlerExceptionResolver")
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext.getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwtToken = getTokenFromRequest(request);
            String subject = tokenClaimsParser.extractSubject(jwtToken);

            AuthUser authUser = validateUserAccessibility(subject);
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

    private AuthUser validateUserAccessibility(String email) {
        User user = userQueryPort.getByEmail(email);
        user.validateActivity();
        return userMapper.toAuthUser(user);
    }

    private void addAuthenticationToContext(AuthUser authUser) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                authUser,
                null,
                Collections.singleton(new SimpleGrantedAuthority(authUser.role().name())));

        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

}
