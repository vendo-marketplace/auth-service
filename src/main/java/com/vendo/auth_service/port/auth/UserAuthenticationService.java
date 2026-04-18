package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.domain.user.model.User;

public interface UserAuthenticationService {

    User getAuthUser();

}
