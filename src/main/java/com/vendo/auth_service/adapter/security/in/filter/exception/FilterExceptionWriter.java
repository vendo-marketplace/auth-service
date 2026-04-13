package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vendo.core_lib.exception.InternalServerException;
import com.vendo.core_lib.util.Require;
import com.vendo.security_lib.exception.response.ExceptionResponse;
import com.vendo.security_lib.filter.ExceptionWriter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
class FilterExceptionWriter implements ExceptionWriter<ExceptionResponse> {

    private final ObjectMapper mapper;

    private final ObjectProvider<HttpServletResponse> providerResponse;

    public void write(ExceptionResponse target) {
        HttpServletResponse response = Require.notNull(providerResponse::getIfAvailable, () -> new InternalServerException("Couldn't provide servlet response. Not http request."));

        response.setStatus(target.getCode());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try {
            response.getWriter().write(mapper.writeValueAsString(target));
        } catch (IOException e) {
            throw new InternalServerException(e.getMessage());
        }
    }
}
