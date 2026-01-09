package com.vendo.auth_service.port.user;

// TODO move to domain because port is a part of application not a part of adapter
import com.vendo.auth_service.adapter.out.user.dto.SaveUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.UpdateUserRequest;
import com.vendo.auth_service.adapter.out.user.dto.User;

public interface UserCommandPort {

    User save(SaveUserRequest saveUserRequest);

    void update(String id, UpdateUserRequest updateUserRequest);

    User ensureExists(String email);

}
