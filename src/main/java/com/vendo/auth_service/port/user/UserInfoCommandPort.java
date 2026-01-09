package com.vendo.auth_service.port.user;

import com.vendo.auth_service.adapter.out.user.dto.SaveUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserInfoRequest;
import com.vendo.auth_service.adapter.out.user.dto.UserInfo;

public interface UserInfoCommandPort {

    UserInfo save(SaveUserInfoRequest saveUserInfoRequest);

    void update(String id, UpdateUserInfoRequest updateUserInfoRequest);

}
