package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.auth_service.adapter.spring.out.ObjectProviderUtil;
import com.vendo.core_lib.exception.ExceptionResponse;
import com.vendo.core_lib.exception.InternalServerException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class FilterExceptionWriter {

    private final ObjectMapper mapper;

    private final ObjectProvider<HttpServletResponse> providerResponse;

    public void write(ExceptionResponse target) {
        HttpServletResponse response = ObjectProviderUtil.getOrThrowIfNotHttpMethodCall(providerResponse);

        response.setStatus(target.getCode());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try {
            response.getWriter().write(mapper.writeValueAsString(target));
        } catch (IOException e) {
            throw new InternalServerException(e.getMessage());
        }
    }
}
