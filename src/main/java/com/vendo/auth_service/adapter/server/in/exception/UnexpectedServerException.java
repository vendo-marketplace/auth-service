package com.vendo.auth_service.adapter.server.in.exception;

public class UnexpectedServerException extends RuntimeException {
    public UnexpectedServerException(String message) {
        super(message);
    }
}
