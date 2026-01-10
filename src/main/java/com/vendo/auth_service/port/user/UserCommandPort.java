package com.vendo.auth_service.port.user;

import com.vendo.auth_service.domain.user.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.dto.User;

public interface UserCommandPort {

    User save(SaveUserRequest saveUserRequest);

    void update(String id, UpdateUserRequest updateUserRequest);

    User ensureExists(String email);

}
