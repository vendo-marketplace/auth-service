package com.vendo.auth_service.port.user;

import com.vendo.auth_service.adapter.out.user.dto.UserInfo;

import java.util.Optional;

public interface UserInfoQueryPort {

    Optional<UserInfo> findByEmail(String email);

}
