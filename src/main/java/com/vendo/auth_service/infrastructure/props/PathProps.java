package com.vendo.auth_service.infrastructure.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "endpoints.unauthenticated")
public class PathProps {

    private Set<String> auth;
    private Set<String> general;
    private Set<String> internal;

    public String[] allPaths() {
        return Stream.of(general, internal, auth)
                .flatMap(Collection::stream)
                .filter(Objects::nonNull)
                .toArray(String[]::new);
    }

}