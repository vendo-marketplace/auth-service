package com.vendo.auth_service.security.service;

import com.vendo.auth_service.http.user.dto.UserInfo;
import com.vendo.auth_service.security.common.dto.TokenPayload;

public interface TokenGenerationService {

    TokenPayload generateTokensPair(UserInfo userInfo);

}
