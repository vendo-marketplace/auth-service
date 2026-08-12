package com.vendo.auth_service.adapter.code.in.exception;

import com.vendo.auth_service.domain.code.exception.InvalidCodeException;
import com.vendo.auth_service.domain.code.exception.CodeAlreadySentException;
import com.vendo.auth_service.domain.code.exception.TooManyCodeRequestsException;
import com.vendo.redis_lib.exception.CodeExpiredException;
import com.vendo.security_lib.exception.ExceptionResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CodeExceptionHandler {

    @ExceptionHandler(CodeAlreadySentException.class)
    public ResponseEntity<ExceptionResponse> handlePasswordRecoveryEventAlreadySentException(CodeAlreadySentException e, HttpServletRequest request) {
        ExceptionResponse exceptionResponse = ExceptionResponse.builder()
                .message(e.getMessage())
                .code(HttpStatus.CONFLICT.value())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.CONFLICT).body(exceptionResponse);
    }

    @ExceptionHandler(TooManyCodeRequestsException.class)
    public ResponseEntity<ExceptionResponse> handleCodeTooManyRequestsException(TooManyCodeRequestsException e, HttpServletRequest request) {
        ExceptionResponse exceptionResponse = ExceptionResponse.builder()
                .message(e.getMessage())
                .code(HttpStatus.TOO_MANY_REQUESTS.value())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(exceptionResponse);
    }

    @ExceptionHandler(InvalidCodeException.class)
    public ResponseEntity<ExceptionResponse> handleInvalidCodeForEmailException(InvalidCodeException e, HttpServletRequest request) {
        ExceptionResponse exceptionResponse = ExceptionResponse.builder()
                .message(e.getMessage())
                .code(HttpStatus.GONE.value())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.GONE).body(exceptionResponse);
    }

    @ExceptionHandler(CodeExpiredException.class)
    public ResponseEntity<ExceptionResponse> handleRedisValueExpiredException(CodeExpiredException e, HttpServletRequest request) {
        ExceptionResponse exceptionResponse = ExceptionResponse.builder()
                .message(e.getMessage())
                .code(HttpStatus.GONE.value())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.GONE).body(exceptionResponse);
    }
}
