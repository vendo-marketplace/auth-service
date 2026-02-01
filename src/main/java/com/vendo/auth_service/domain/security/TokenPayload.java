package com.vendo.auth_service.domain.security;

import lombok.Builder;

@Builder
public record TokenPayload(
        String accessToken,
        String refreshToken) {
}
