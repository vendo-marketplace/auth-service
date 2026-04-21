package com.vendo.auth_service.domain.auth.dto;

import com.vendo.auth_service.application.auth.dto.TokenPayload;

public class TokenPayloadDataBuilder {

    public static TokenPayload.TokenPayloadBuilder withAllFields() {
        return TokenPayload.builder()
                .accessToken("test_access_token")
                .refreshToken("test_refresh_token");
    }

}
