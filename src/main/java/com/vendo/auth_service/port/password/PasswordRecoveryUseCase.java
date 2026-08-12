package com.vendo.auth_service.port.password;

import com.vendo.auth_service.application.password.command.ResetPasswordCommand;

public interface PasswordRecoveryUseCase {

    void forgot(String email);

    void reset(String code, ResetPasswordCommand command);

    void resend(String email);

}
