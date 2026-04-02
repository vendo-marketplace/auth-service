package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class FilterExceptionParser implements ExceptionParser {

    private final List<ExceptionWrapper> wrappers;

    @Override
    public ExceptionResponse parse(Exception e) {
        ExceptionWrapper wrapper = wrappers.stream()
                .filter(aClass -> aClass.getException().equals(e.getClass()))
                .findFirst()
                // TODO internal server error
                .orElseThrow(() -> new RuntimeException("No exception found."));
        return wrapper.getResponse();
    }

}
