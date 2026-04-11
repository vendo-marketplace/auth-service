package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.security_lib.resolver.AntPathResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;

@Component
public class AuthAntPathResolver implements AntPathResolver {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public static final String[] PERMITTED_PATHS = new String[] {
            "/auth/sign-in",
            "/auth/sign-up",
            "/auth/refresh",
            "/auth/google",
            "/password/**",
            "/verification/**",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/actuator/health"
    };

    @Override
    public boolean isPermittedPath(String path) {
        return Arrays.stream(PERMITTED_PATHS).anyMatch(pr -> antPathMatcher.match(pr, path));
    }

}
