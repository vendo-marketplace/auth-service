package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.adapter.security.out.config.GatewayProps;
import com.vendo.security_lib.resolver.AntPathResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

@Component
@RequiredArgsConstructor
public class AuthAntPathResolver implements AntPathResolver {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private final GatewayProps props;

    @Override
    public boolean isPermittedPath(String path) {
        return props.allPaths().stream()
                .anyMatch(pr -> antPathMatcher.match(pr, path));
    }

}
