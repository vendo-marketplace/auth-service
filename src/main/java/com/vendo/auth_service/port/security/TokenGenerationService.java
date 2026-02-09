package com.vendo.auth_service.port.security;

import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.domain.security.dto.TokenPayload;

public interface TokenGenerationService {

    TokenPayload generate(User user);

}
