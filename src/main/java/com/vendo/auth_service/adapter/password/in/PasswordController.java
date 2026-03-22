package com.vendo.auth_service.adapter.password.in;

import com.vendo.auth_service.adapter.password.out.mapper.PasswordMapper;
import com.vendo.auth_service.application.password.PasswordRecoveryService;
import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/password")
public class PasswordController {

    private final PasswordMapper passwordMapper;

    private final PasswordRecoveryService passwordRecoveryService;

    @PostMapping("/forgot")
    void forgotPassword(@RequestParam String email) {
        passwordRecoveryService.forgotPassword(email);
    }

    @PutMapping("/reset")
    void resetPassword(
            @RequestParam String otp,
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        passwordRecoveryService.resetPassword(otp, passwordMapper.toCommand(request));
    }

    @PutMapping("/resend-otp")
    void resendOtp(@RequestParam String email) {
        passwordRecoveryService.resendOtp(email);
    }

}
