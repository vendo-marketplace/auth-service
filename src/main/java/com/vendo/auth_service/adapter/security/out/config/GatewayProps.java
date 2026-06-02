package com.vendo.auth_service.adapter.security.out.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "gateway.security.paths")
public class GatewayProps {

    private List<String> auth;

}