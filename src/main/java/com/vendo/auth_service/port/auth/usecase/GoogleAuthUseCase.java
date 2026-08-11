package com.vendo.auth_service.port.auth.usecase;

import com.vendo.auth_service.adapter.auth.in.dto.GoogleAuthRequest;
import com.vendo.auth_service.application.auth.dto.AuthResponse;

public interface GoogleAuthUseCase {

    AuthResponse auth(GoogleAuthRequest request);

}
