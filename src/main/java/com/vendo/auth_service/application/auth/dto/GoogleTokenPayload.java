package com.vendo.auth_service.application.auth.dto;

import lombok.Builder;

@Builder
public record GoogleTokenPayload(

        String email,
        String fullName

) {
}
