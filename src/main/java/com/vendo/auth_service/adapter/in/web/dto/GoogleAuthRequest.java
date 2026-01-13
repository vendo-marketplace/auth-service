package com.vendo.auth_service.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record GoogleAuthRequest(@NotBlank(message = "Id Token is required.") String idToken) {
}
