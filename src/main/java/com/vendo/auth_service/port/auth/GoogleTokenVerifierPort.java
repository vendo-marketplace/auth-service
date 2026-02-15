package com.vendo.auth_service.port.auth;

import com.vendo.auth_service.application.auth.dto.GoogleTokenPayload;

public interface GoogleTokenVerifierPort {

        GoogleTokenPayload verify(String idToken);

}
