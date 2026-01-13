package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.adapter.out.security.common.dto.TokenPayload;

public class TokenPayloadDataBuilder {

    public static TokenPayload.TokenPayloadBuilder buildTokenPayloadWithAllFields() {
        return TokenPayload.builder()
                .accessToken("test_access_token")
                .refreshToken("test_refresh_token");
    }
}
