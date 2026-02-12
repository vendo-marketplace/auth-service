package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.domain.auth.dto.AuthUser;

public interface UserAuthenticationService {

    AuthUser getAuthUser();

}
