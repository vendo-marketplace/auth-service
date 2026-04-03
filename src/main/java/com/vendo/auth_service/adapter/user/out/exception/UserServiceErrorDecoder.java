package com.vendo.auth_service.adapter.user.out.exception;

import com.vendo.core_lib.exception.InternalServerException;
import com.vendo.core_lib.type.ServiceName;
import com.vendo.user_lib.exception.UserAlreadyExistsException;
import com.vendo.user_lib.exception.UserNotFoundException;
import feign.Response;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class UserServiceErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String s, Response response) {

        if (HttpStatus.valueOf(response.status()).is5xxServerError()) {
            return new UserServiceUnavailableException(ServiceName.USER_SERVICE + " is unavailable.");
        }

        if (HttpStatus.NOT_FOUND.value() == response.status()) {
            return new UserNotFoundException("User not found.");
        }

        if (HttpStatus.CONFLICT.value() == response.status()) {
            return new UserAlreadyExistsException("User already exists.");
        }

        log.error(response.toString());
        return new InternalServerException("Internal server error.");
    }

}
