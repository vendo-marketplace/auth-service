package com.vendo.auth_service.port.user;

import com.vendo.auth_service.domain.user.model.User;

public interface UserCommandPort {

    User save(User user);

    void update(String id, User user);

    User ensureExists(String email);

}
