package com.vendo.auth_service.adapter.security.in.filter.exception.wrappers;

import com.vendo.auth_service.adapter.spring.out.ObjectProviderUtil;
import com.vendo.core_lib.exception.ExceptionResponse;
import com.vendo.security_lib.exception.ExceptionWrapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtWrapper implements ExceptionWrapper<ExceptionResponse> {

    private final ObjectProvider<HttpServletRequest> providerRequest;

    @Override
    public ExceptionResponse getResponse(Exception e) {
        HttpServletRequest request = ObjectProviderUtil.getOrThrowIfNotHttpMethodCall(providerRequest);

        return ExceptionResponse.builder()
                .code(HttpStatus.UNAUTHORIZED.value())
                .message("Invalid or expired token.")
                .path(request.getRequestURI())
                .build();
    }

    @Override
    public Class<? extends Exception> getException() {
        return JwtException.class;
    }
}
