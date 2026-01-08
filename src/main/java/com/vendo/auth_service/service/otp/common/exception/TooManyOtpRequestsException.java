package com.vendo.auth_service.service.otp.common.exception;

public class TooManyOtpRequestsException extends RuntimeException {
  public TooManyOtpRequestsException(String message) {
    super(message);
  }
}
