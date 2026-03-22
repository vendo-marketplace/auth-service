package com.vendo.auth_service.adapter.user.out.config;

import com.vendo.auth_service.adapter.user.out.exception.UserServiceErrorDecoder;
import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserFeignConfig {

    @Bean
    public ErrorDecoder errorDecoder() {
        return new UserServiceErrorDecoder();
    }

}
