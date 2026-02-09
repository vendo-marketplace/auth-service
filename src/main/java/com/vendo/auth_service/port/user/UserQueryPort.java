package com.vendo.auth_service.port.user;

import com.vendo.auth_service.domain.user.model.User;

public interface UserQueryPort {

    User getByEmail(String email);

    boolean existsByEmail(String email);

}
