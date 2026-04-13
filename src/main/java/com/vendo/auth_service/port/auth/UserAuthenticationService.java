package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.application.auth.dto.AuthUserResponse;
import com.vendo.auth_service.domain.user.model.User;

public interface UserAuthenticationService {

    AuthUserResponse getAuthUser();

    User getUser(String email);

}
