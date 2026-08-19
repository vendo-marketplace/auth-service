package com.vendo.auth_service.port.auth.usecase;

import com.vendo.auth_service.application.auth.dto.AuthResponse;

public interface GoogleAuthUseCase {

    AuthResponse auth(String authCode);

}
