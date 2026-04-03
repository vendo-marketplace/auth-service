package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DefaultFilterExceptionHandler implements FilterExceptionHandler {

    private final FilterExceptionParser parser;
    private final FilterExceptionWriter writer;

    @Override
    public void handle(Exception e) {
        ExceptionResponse payload = parser.parse(e);
        writer.write(payload);
    }
}
