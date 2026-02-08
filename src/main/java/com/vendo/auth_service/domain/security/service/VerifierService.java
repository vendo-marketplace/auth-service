package com.vendo.auth_service.domain.security.service;

import com.vendo.auth_service.domain.user.common.exception.UserAlreadyExistsException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class VerifierService {
    public void throwIfExists(boolean b){
        if(b){
            throw new UserAlreadyExistsException("User already exists.");
        }
    }
    public void matchPasswordsOrThrow(boolean b) {
        if (!b) {
            throw new BadCredentialsException("Wrong credentials");
        }
    }
}
