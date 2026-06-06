package com.vendo.auth_service.adapter.security.out.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "gateway.security.paths")
public class GatewayProps {

    private Set<String> auth;
    private Set<String> general;
    private Set<String> internal;
    private Set<String> product;
    private Set<String> search;

    public Set<String> allPaths() {
        return flatLists(List.of(general, internal, product, auth, search));
    }

    public String[] allPathsArray() {
        return allPaths().toArray(String[]::new);
    }

    private static Set<String> flatLists(List<Set<String>> lists) {
        return lists.stream()
                .flatMap(Collection::stream)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

}