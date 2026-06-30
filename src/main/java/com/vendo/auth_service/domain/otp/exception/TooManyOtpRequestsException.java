package com.vendo.auth_service.domain.otp.exception;

public class TooManyOtpRequestsException extends RuntimeException {

    public TooManyOtpRequestsException(String message) {
    super(message);
  }

}
