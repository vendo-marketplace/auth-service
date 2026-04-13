package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.security_lib.exception.ExceptionHandler;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.security_lib.filter.ExceptionWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class FilterExceptionHandler implements ExceptionHandler {

    private final FilterExceptionFactory exceptionFactory;
    private final ExceptionWriter<ExceptionResponse> writer;

    @Override
    public void handle(Exception e) {
        ExceptionResponse payload = exceptionFactory.get(e);
        writer.write(payload);
    }
}
