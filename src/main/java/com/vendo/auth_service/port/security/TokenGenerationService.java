package com.vendo.auth_service.port.security;

import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;

public interface TokenGenerationService {

    TokenPayload generate(User user);

}
