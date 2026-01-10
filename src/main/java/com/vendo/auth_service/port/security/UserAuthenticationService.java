package com.vendo.auth_service.port.security;

import com.vendo.auth_service.adapter.in.security.dto.AuthUser;

public interface UserAuthenticationService {

    AuthUser getAuthenticatedUser();

}
