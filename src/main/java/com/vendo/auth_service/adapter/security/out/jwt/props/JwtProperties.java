package com.vendo.auth_service.adapter.security.out.jwt.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "security.jwt")
public class JwtProperties {

    private Secret secret;
    private Internal internal;

    public record Secret(
            String key,
            long accessExpirationTime,
            long refreshExpirationTime
    ) { }

    public record Internal(String key, long expirationTime) { }

}
