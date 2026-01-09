package com.vendo.auth_service.application.otp.common.exception;

public class TooManyOtpRequestsException extends RuntimeException {
  public TooManyOtpRequestsException(String message) {
    super(message);
  }
}
