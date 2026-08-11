package com.vendo.auth_service.adapter.password.in;

import com.vendo.auth_service.adapter.password.out.mapper.PasswordMapper;
import com.vendo.auth_service.adapter.password.in.dto.ResetPasswordRequest;
import com.vendo.auth_service.port.password.PasswordRecoveryUseCase;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/password")
public class PasswordController {

    private final PasswordMapper passwordMapper;

    private final PasswordRecoveryUseCase passwordRecoveryUseCase;

    @PostMapping("/forgot")
    void forgot(@RequestParam String email) {
        passwordRecoveryUseCase.forgot(email);
    }

    @PutMapping("/reset")
    void reset(
            @RequestParam String code,
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        passwordRecoveryUseCase.reset(code, passwordMapper.toCommand(request));
    }

    @PutMapping("/resend")
    void resend(@RequestParam String email) {
        passwordRecoveryUseCase.resend(email);
    }

}
