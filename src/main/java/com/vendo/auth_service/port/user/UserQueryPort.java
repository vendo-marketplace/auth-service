package com.vendo.auth_service.port.user;

import com.vendo.auth_service.domain.user.dto.User;

import java.util.Optional;

public interface UserQueryPort {

    User getByEmail(String email);

}
