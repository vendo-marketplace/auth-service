package com.vendo.auth_service.domain.user.common.exception;

public class UserAlreadyActivatedException extends RuntimeException {
  public UserAlreadyActivatedException(String message) {
    super(message);
  }
}
