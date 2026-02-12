package com.vendo.auth_service.domain.user.service;

import com.vendo.auth_service.domain.user.exception.UserAlreadyActivatedException;
import com.vendo.auth_service.domain.user.exception.UserAlreadyExistsException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.exception.UserBlockedException;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    public void throwIfExists(boolean b){
        if(b){
            throw new UserAlreadyExistsException("User already exists.");
        }
    }

    public void validateBeforeActivation(User user) {
        UserStatus status = user.getStatus();
        throwIfBlocked(status);
        throwIfActive(status);
    }

    private void throwIfBlocked(UserStatus userStatus) {
        if (userStatus == UserStatus.BLOCKED) {
            throw new UserBlockedException("User is blocked.");
        }
    }

    private void throwIfActive(UserStatus userStatus) {
        if (userStatus == UserStatus.ACTIVE) {
            throw new UserAlreadyActivatedException("User account is already activated.");
        }
    }
}
