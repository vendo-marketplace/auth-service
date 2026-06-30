package com.vendo.auth_service.domain.otp.exception;

public class OtpAlreadySentException extends RuntimeException {

    public OtpAlreadySentException(String message) {
        super(message);
    }

}
