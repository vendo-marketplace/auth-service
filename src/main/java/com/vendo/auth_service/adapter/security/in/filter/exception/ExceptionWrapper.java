package com.vendo.auth_service.adapter.security.in.filter.exception;

import com.vendo.core_lib.exception.ExceptionResponse;

public interface ExceptionWrapper {

    ExceptionResponse getResponse(Exception e);

    Class<? extends Exception> getException();

}
