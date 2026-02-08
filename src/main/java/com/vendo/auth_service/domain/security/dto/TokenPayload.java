package com.vendo.auth_service.domain.security.dto;

import lombok.Builder;

@Builder
public record TokenPayload(
        String accessToken,
        String refreshToken) {
}
