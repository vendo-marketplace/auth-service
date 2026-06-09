package com.vendo.auth_service.adapter.security.out.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "gateway.security.paths")
public class GatewayProps {

    private Set<String> auth;
    private Set<String> general;
    private Set<String> internal;

    public String[] allPaths() {
        return mergePaths(List.of(general, internal, auth));
    }

    private static String[] mergePaths(List<Set<String>> lists) {
        return lists.stream()
                .flatMap(Collection::stream)
                .filter(Objects::nonNull)
                .toArray(String[]::new);
    }

}