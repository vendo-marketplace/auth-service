package com.vendo.auth_service.domain.user.exception;

public class UserAlreadyCompletedException extends RuntimeException {
  public UserAlreadyCompletedException(String message) {
    super(message);
  }
}
