package com.vendo.auth_service.domain.code.exception;

public class InvalidCodeException extends RuntimeException {

    public InvalidCodeException(String message) {
        super(message);
    }

}
