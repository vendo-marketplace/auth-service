package com.vendo.auth_service.adapter.security.in.filter;

import com.vendo.auth_service.infrastructure.props.PathProps;
import com.vendo.security_lib.resolver.AntPathResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class AuthAntPathResolver implements AntPathResolver {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private final PathProps props;

    @Override
    public boolean isPermittedPath(String path) {
        return Arrays.stream(props.allPaths())
                .anyMatch(pr -> antPathMatcher.match(pr, path));
    }

}
