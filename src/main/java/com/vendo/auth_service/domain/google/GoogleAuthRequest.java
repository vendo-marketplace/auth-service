package com.vendo.auth_service.domain.google;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record GoogleAuthRequest(@NotBlank(message = "Id Token is required.") String idToken) {
}
