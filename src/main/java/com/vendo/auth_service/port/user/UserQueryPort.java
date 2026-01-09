package com.vendo.auth_service.port.user;

import com.vendo.auth_service.adapter.out.user.dto.User;

import java.util.Optional;

public interface UserQueryPort {

    Optional<User> findByEmail(String email);

    User getByEmail(String email);

}
