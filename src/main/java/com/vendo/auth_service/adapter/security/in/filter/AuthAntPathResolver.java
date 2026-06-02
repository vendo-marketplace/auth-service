package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.adapter.security.out.config.GatewayProps;
import com.vendo.security_lib.resolver.AntPathResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class AuthAntPathResolver implements AntPathResolver {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private final GatewayProps permittedPaths;

    @Override
    public boolean isPermittedPath(String path) {
       return permittedPaths.getAuth().stream()
               .anyMatch(pr -> antPathMatcher.match(pr, path));
    }

}
