package com.vendo.auth_service.port.user;

import com.vendo.auth_service.domain.user.common.dto.SaveUserRequest;
import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.domain.user.common.type.ProviderType;

public interface UserCommandPort {

    User save(SaveUserRequest saveUserRequest);

    void update(String id, UpdateUserRequest updateUserRequest);

    User ensureExists(String email);

}
