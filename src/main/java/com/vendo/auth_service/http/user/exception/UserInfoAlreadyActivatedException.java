package com.vendo.auth_service.http.user.exception;

public class UserInfoAlreadyActivatedException extends RuntimeException {
  public UserInfoAlreadyActivatedException(String message) {
    super(message);
  }
}
