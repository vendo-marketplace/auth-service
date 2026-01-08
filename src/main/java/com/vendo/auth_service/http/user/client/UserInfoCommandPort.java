package com.vendo.auth_service.http.user.client;

import com.vendo.auth_service.http.user.dto.SaveUserInfoRequest;
import com.vendo.auth_service.http.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.http.user.dto.UserInfo;

public interface UserInfoCommandPort {

    UserInfo save(SaveUserInfoRequest saveUserInfoRequest);

    void update(String id, UpdateUserInfoRequest updateUserInfoRequest);

}
