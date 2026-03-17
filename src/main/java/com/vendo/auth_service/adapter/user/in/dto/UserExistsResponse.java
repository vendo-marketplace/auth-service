package com.vendo.auth_service.adapter.user.in.dto;

import lombok.Builder;

@Builder
public record UserExistsResponse(

        String status,
        boolean exists

) {
}
