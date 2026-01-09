package com.vendo.auth_service.adapter.out.user.exception;

public class UserInfoAlreadyExistsException extends RuntimeException {
    public UserInfoAlreadyExistsException(String message) {
        super(message);
    }
}
