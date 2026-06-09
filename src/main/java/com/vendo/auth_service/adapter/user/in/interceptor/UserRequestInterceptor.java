package com.vendo.auth_service.adapter.user.in.interceptor;

import com.vendo.auth_service.adapter.security.out.jwt.InternalTokenGenerationPort;
import feign.RequestInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.vendo.security_lib.http.HttpUtils.AUTHORIZATION_HEADER;
import static com.vendo.security_lib.http.HttpUtils.BEARER_PREFIX;

@Configuration
@RequiredArgsConstructor
public class UserRequestInterceptor {

    private final InternalTokenGenerationPort internalTokenGenerationPort;

    @Bean
    RequestInterceptor internalUserInfoInterceptor() {
        return request -> request.header(AUTHORIZATION_HEADER, BEARER_PREFIX + internalTokenGenerationPort.generateInternal());
    }

}
