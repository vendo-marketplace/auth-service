package com.vendo.auth_service.adapter.auth.in.dto;

import com.vendo.auth_service.domain.user.pattern.UserRegexPatterns;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record CompleteAuthRequest(

        @NotNull(message = "Full name is required.")
        @Pattern(regexp = UserRegexPatterns.FULL_NAME, message = "Full name must contain two words, each starting with an uppercase letter and followed by lowercase letters.")
        String fullName

) {
}
