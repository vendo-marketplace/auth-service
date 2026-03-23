package com.vendo.auth_service.port.user;

import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.model.User;

public interface UserCommandPort {

    User save(User user);

    void update(String id, UpdateUserRequest request);

    User ensureExists(String email);

}
