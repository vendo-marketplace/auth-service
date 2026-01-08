package com.vendo.auth_service.http.user.exception;

public class UserInfoAlreadyExistsException extends RuntimeException {
    public UserInfoAlreadyExistsException(String message) {
        super(message);
    }
}
