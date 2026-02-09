package com.vendo.auth_service.domain.user.exception;

public class UserAlreadyActivatedException extends RuntimeException {
  public UserAlreadyActivatedException(String message) {
    super(message);
  }
}
