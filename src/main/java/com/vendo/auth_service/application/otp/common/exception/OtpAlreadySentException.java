package com.vendo.auth_service.application.otp.common.exception;

public class OtpAlreadySentException extends RuntimeException {
    public OtpAlreadySentException(String message) {
        super(message);
    }
}
