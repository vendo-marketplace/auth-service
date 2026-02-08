package com.vendo.auth_service.port.security;

import com.vendo.auth_service.domain.security.dto.AuthUser;

public interface UserAuthenticationService {

    AuthUser getAuthUser();

}
