package com.vendo.auth_service.adapter.verification.in;

import com.vendo.auth_service.application.auth.EmailVerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
    void validate(@RequestParam String otp) {
        emailVerificationService.validate(otp);
    }

}

