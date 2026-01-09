package com.vendo.auth_service.adapter.in.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record RefreshRequest(
    @NotBlank(message = "Refresh token is required.")
    String refreshToken) {
}
