package com.vendo.auth_service.adapter.verification.in;

import com.vendo.auth_service.port.auth.usecase.EmailVerificationUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/verification")
public class VerificationController {

    private final EmailVerificationUseCase emailVerificationUseCase;

    @PostMapping("/send")
    void send(@RequestParam String email) {
        emailVerificationUseCase.send(email);
    }

    @PostMapping("/resend")
    void resend(@RequestParam String email) {
        emailVerificationUseCase.resend(email);
    }

    @PostMapping("/validate")
    void validate(@RequestParam String code) {
        emailVerificationUseCase.validate(code);
    }

}

