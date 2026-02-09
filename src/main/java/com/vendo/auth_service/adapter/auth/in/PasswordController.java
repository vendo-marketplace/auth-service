package com.vendo.auth_service.adapter.auth.in;

import com.vendo.auth_service.application.password.PasswordRecoveryService;
import com.vendo.auth_service.domain.otp.dto.ResetPasswordRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/password")
public class PasswordController {

    private final PasswordRecoveryService passwordRecoveryService;

    @PostMapping("/forgot")
    void forgotPassword(@RequestParam String email) {
        passwordRecoveryService.forgotPassword(email);
    }

    @PutMapping("/reset")
    void resetPassword(
            @RequestParam String otp,
            @Valid @RequestBody ResetPasswordRequest resetPasswordRequest
    ) {
        passwordRecoveryService.resetPassword(otp, resetPasswordRequest);
    }

    @PutMapping("/resend-otp")
    void resendOtp(@RequestParam String email) {
        passwordRecoveryService.resendOtp(email);
    }

}
