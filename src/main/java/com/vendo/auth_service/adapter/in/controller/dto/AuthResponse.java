package com.vendo.auth_service.adapter.in.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record AuthResponse (
        @JsonProperty("access-token")
        String accessToken,

        @JsonProperty("refresh-token")
        String refreshToken) {
}
