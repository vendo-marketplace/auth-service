package com.vendo.auth_service.domain.code.exception;

public class CodeAlreadySentException extends RuntimeException {

    public CodeAlreadySentException(String message) {
        super(message);
    }

}
