package com.vendo.auth_service.port.google;

import com.vendo.auth_service.domain.google.GoogleTokenPayload;

public interface GoogleTokenVerifierPort {

        GoogleTokenPayload verify(String idToken);

}
