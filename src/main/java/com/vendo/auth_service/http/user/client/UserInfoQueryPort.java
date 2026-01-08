package com.vendo.auth_service.http.user.client;

import com.vendo.auth_service.http.user.dto.UserInfo;

import java.util.Optional;

public interface UserInfoQueryPort {

    Optional<UserInfo> findByEmail(String email);

}
