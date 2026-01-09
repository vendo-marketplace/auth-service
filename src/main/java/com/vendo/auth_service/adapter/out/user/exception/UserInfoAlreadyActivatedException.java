package com.vendo.auth_service.adapter.out.user.exception;

public class UserInfoAlreadyActivatedException extends RuntimeException {
  public UserInfoAlreadyActivatedException(String message) {
    super(message);
  }
}
