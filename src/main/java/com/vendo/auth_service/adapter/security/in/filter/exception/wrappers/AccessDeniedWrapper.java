package com.vendo.auth_service.adapter.security.in.filter.exception.wrappers;

import com.vendo.auth_service.adapter.security.in.filter.exception.ExceptionWrapper;
import com.vendo.auth_service.adapter.server.out.util.ObjectProviderUtil;
import com.vendo.core_lib.exception.ExceptionResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AccessDeniedWrapper implements ExceptionWrapper {

    private final ObjectProvider<HttpServletRequest> providerRequest;

    @Override
    public ExceptionResponse getResponse(Exception e) {
        HttpServletRequest request = ObjectProviderUtil.getOrThrowIfNotHttpMethodCall(providerRequest);

        return ExceptionResponse.builder()
                .code(HttpStatus.FORBIDDEN.value())
                .message("Unreachable resource.")
                .path(request.getRequestURI())
                .build();
    }

    @Override
    public Class<? extends Exception> getException() {
        return AccessDeniedException.class;
    }

}
