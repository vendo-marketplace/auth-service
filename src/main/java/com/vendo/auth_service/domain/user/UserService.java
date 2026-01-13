package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.domain.user.common.exception.UserAlreadyActivatedException;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.domain.user.common.type.UserStatus;
import com.vendo.security.common.exception.UserBlockedException;
import org.springframework.stereotype.Service;

@Service
public class UserService {

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
