package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.InternalServerException;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.security_lib.filter.ExceptionWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
class FilterExceptionFactory {

    private final List<ExceptionWrapper<ExceptionResponse>> wrappers;

    public ExceptionResponse get(Exception e) {
        ExceptionWrapper<ExceptionResponse> wrapper = wrappers.stream()
                .filter(eWrapper -> eWrapper.getException().isInstance(e))
                .findFirst()
                .orElseThrow(() -> new InternalServerException("No exception wrapper found for %s.".formatted(e.getClass())));
        return wrapper.getResponse(e);
    }

}
