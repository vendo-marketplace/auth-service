package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.adapter.security.out.dto.AuthUser;
import com.vendo.auth_service.application.auth.dto.AuthUserResponse;

public interface UserAuthenticationService {

    AuthUserResponse getAuthUser();

    AuthUser retrieveAuthUser(String email);

}
