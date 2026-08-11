package com.vendo.auth_service.domain.code.exception;

public class TooManyCodeRequestsException extends RuntimeException {

    public TooManyCodeRequestsException(String message) {
    super(message);
  }

}
