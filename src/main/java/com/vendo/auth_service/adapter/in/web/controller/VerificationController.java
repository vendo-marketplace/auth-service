package com.vendo.auth_service.adapter.in.web.controller;

import com.vendo.auth_service.application.EmailVerificationService;
import com.vendo.auth_service.system.redis.common.dto.ValidateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/verification")
public class VerificationController {

    private final EmailVerificationService emailVerificationService;

    @PostMapping("/send-otp")
    void sendOtp(@RequestParam String email) {
        emailVerificationService.sendOtp(email);
    }

    @PostMapping("/resend-otp")
    void resendOtp(@RequestParam String email) {
        emailVerificationService.resendOtp(email);
    }

    @PostMapping("/validate")
    void validate(
            @RequestParam String otp,
            @Valid @RequestBody ValidateRequest validateRequest
    ) {
        emailVerificationService.validate(otp, validateRequest);
    }

}

