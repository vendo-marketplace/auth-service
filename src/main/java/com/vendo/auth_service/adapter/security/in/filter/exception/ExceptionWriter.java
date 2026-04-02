package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;

public interface ExceptionWriter {

    void write(ExceptionResponse target);

}
