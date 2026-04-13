package com.vendo.auth_service.adapter.security.in.filter.exception.wrappers;

import com.vendo.core_lib.exception.InternalServerException;
import com.vendo.core_lib.util.Require;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.security_lib.filter.ExceptionWrapper;
import com.vendo.user_lib.exception.UserBlockedException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class UserBlockedWrapper implements ExceptionWrapper<ExceptionResponse> {

    private final ObjectProvider<HttpServletRequest> providerRequest;

    @Override
    public ExceptionResponse getResponse(Exception e) {
        HttpServletRequest request = Require.notNull(providerRequest::getIfAvailable, () -> new InternalServerException("Not http request."));

        return ExceptionResponse.builder()
                .code(HttpStatus.FORBIDDEN.value())
                .message(e.getMessage())
                .path(request.getRequestURI())
                .build();
    }

    @Override
    public Class<? extends Exception> getException() {
        return UserBlockedException.class;
    }
}
