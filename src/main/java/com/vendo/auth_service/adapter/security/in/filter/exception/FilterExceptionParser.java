package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;
import com.vendo.core_lib.exception.InternalServerException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class FilterExceptionParser {

    private final List<ExceptionWrapper> wrappers;

    public ExceptionResponse parse(Exception e) {
        ExceptionWrapper wrapper = wrappers.stream()
                .filter(eWrapper -> eWrapper.getException().isInstance(e))
                .findFirst()
                .orElseThrow(() -> new InternalServerException("No exception wrapper found for %s.".formatted(e.getClass())));
        return wrapper.getResponse(e);
    }

}
