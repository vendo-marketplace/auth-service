package com.vendo.auth_service.domain.google;

import lombok.Builder;

@Builder
public record GoogleTokenPayload(

        String email,
        String fullName

) {
}
