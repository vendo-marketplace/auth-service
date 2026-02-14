package com.vendo.auth_service.adapter.user.in.interceptor;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.vendo.security.common.constants.AuthConstants.X_INTERNAL_API_KEY_HEADER;

@Configuration
public class UserRequestInterceptor {

    @Value("${security.internal.api-key}")
    private String INTERNAL_API_TOKEN;

    @Bean
    RequestInterceptor internalUserInfoInterceptor() {
        return request -> request.header(X_INTERNAL_API_KEY_HEADER, INTERNAL_API_TOKEN);
    }
}
