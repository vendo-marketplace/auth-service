package com.vendo.auth_service.domain.user;

import com.vendo.auth_service.adapter.out.user.dto.User;
import com.vendo.auth_service.adapter.out.user.exception.UserAlreadyExistsException;
import com.vendo.auth_service.adapter.out.user.exception.UserNotFoundException;
import com.vendo.auth_service.port.user.UserQueryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserQueryPort userQueryPort;

    public User getUserInfoOrThrow(String email) {
        Optional<User> optionalUserInfo = userQueryPort.findByEmail(email);

        if (optionalUserInfo.isEmpty()) {
            throw new UserNotFoundException("User not found.");
        }

        return optionalUserInfo.get();
    }

    public void throwIfUserInfoExists(String email) {
        Optional<User> optionalUserInfo = userQueryPort.findByEmail(email);

        if (optionalUserInfo.isPresent()) {
            throw new UserAlreadyExistsException("User already exists.");
        }
    }
}
