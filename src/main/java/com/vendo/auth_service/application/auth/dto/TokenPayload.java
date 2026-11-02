package com.vendo.auth_service.application.auth.dto;

import lombok.Builder;

@Builder
public record TokenPayload(

        String accessToken,
        String refreshToken

) {

    public static TokenPayload empty() {
        return new TokenPayload("", "");
    }

}
