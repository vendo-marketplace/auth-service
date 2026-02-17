package com.vendo.auth_service.infrastructure.config.http;

import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableFeignClients(basePackages = "com.vendo.auth_service.adapter.user.out")
public class OpenFeignConfig {
}
