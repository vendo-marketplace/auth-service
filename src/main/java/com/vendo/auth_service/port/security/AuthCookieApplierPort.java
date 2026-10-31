package com.vendo.auth_service.port.security;

import com.vendo.auth_service.application.auth.dto.TokenPayload;

public interface AuthCookieApplierPort {

    void apply(TokenPayload payload);

}
