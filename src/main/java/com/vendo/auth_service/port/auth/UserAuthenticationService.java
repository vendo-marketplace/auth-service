package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.application.auth.dto.AuthUserResponse;

public interface UserAuthenticationService {

    AuthUserResponse getAuthUser();

}
