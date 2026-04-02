package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.core_lib.exception.ExceptionResponse;
import com.vendo.core_lib.exception.InternalServerException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class FilterExceptionWriter implements ExceptionWriter {

    private final ObjectProvider<HttpServletRequest> providerRequest;
    private final ObjectProvider<HttpServletResponse> providerResponse;
    private final ObjectMapper mapper;

    @Override
    public void write(ExceptionResponse target) {
        HttpServletResponse response = getOrThrowIfNotHttpMethodCall(providerResponse);
        HttpServletRequest request = getOrThrowIfNotHttpMethodCall(providerRequest);

        response.setStatus(target.getCode());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ExceptionResponse exceptionResponse = ExceptionResponse.builder()
                .code(target.getCode())
                .path(request.getRequestURI())
                .message(target.getMessage())
                .build();

        try {
            response.getWriter().write(mapper.writeValueAsString(exceptionResponse));
        } catch (IOException e) {
            // TODO throw internal server error
            throw new InternalServerException(e.getMessage());
        }
    }

    private <T> T getOrThrowIfNotHttpMethodCall(ObjectProvider<T> provider) {
        T value = provider.getIfAvailable();

        if (value == null) {
            // TODO throw something like internal server error
            throw new RuntimeException("Couldn't inject servlet dependecies, because not a http method call.");
        }

        return value;
    }

}
