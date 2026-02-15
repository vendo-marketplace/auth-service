package com.vendo.auth_service.adapter.user.in.interceptor;

import com.vendo.auth_service.adapter.security.out.jwt.InternalTokenGenerationService;
import feign.RequestInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.vendo.security.common.constants.AuthConstants.*;

@Configuration
@RequiredArgsConstructor
public class UserRequestInterceptor {

    private final InternalTokenGenerationService internalTokenGenerationService;

    @Bean
    RequestInterceptor internalUserInfoInterceptor() {
        return request -> request.header(AUTHORIZATION_HEADER, BEARER_PREFIX + internalTokenGenerationService.generateInternal());
    }
}
