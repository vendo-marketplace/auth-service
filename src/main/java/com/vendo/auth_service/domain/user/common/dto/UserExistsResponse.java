package com.vendo.auth_service.domain.user.common.dto;

import lombok.Builder;

@Builder
public record UserExistsResponse(
        String status,
        boolean exists) {
}
