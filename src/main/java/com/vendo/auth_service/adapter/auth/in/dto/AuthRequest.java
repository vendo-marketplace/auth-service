package com.vendo.auth_service.adapter.auth.in.dto;

import com.vendo.auth_service.domain.user.pattern.UserRegexPatterns;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record AuthRequest(

        @NotNull(message = "Email is required.")
        @Pattern(regexp = UserRegexPatterns.EMAIL, message = "Invalid email. Example format: example@domain.com")
        String email,

        @NotNull(message = "Password is required.")
        @Pattern(regexp = UserRegexPatterns.PASSWORD, message = "Invalid password. Should include minimum 8 characters, 1 uppercase character, 1 lowercase character, 1 special symbol.")
        String password

) {
}
