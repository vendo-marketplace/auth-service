package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class DefaultFilterExceptionHandler implements FilterExceptionHandler {

    private final Set<Class<? extends Exception>> IGNORE_EXCEPTIONS = Set.of(AccessDeniedException.class, JwtException.class);
    private final ExceptionParser parser;
    private final ExceptionWriter writer;

    @Override
    public void handle(Exception e) throws Exception {
        if (doIgnore(e)) throw e;
        ExceptionResponse payload = parser.parse(e);
        writer.write(payload);
    }

    private boolean doIgnore(Exception e) {
        return IGNORE_EXCEPTIONS.stream()
                .anyMatch(aClass -> aClass.isInstance(e));
    }

}
