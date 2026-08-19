package com.vendo.auth_service.domain.user.exception;

public class GoogleAuthException extends RuntimeException {
    public GoogleAuthException(String message) {
        super(message);
    }
}
