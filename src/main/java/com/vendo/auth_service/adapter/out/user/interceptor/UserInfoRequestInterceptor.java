package com.vendo.auth_service.adapter.out.user.interceptor;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.vendo.security.common.constants.AuthConstants.AUTHORIZATION_HEADER;
import static com.vendo.security.common.constants.AuthConstants.BEARER_PREFIX;

@Configuration
public class UserInfoRequestInterceptor {

    // TODO rename
    @Value("${user-internal-token}")
    private String USER_INTERNAL_TOKEN;

    @Bean
    RequestInterceptor internalUserInfoInterceptor() {
        return request -> request.header(AUTHORIZATION_HEADER, BEARER_PREFIX + USER_INTERNAL_TOKEN);
    }
}
