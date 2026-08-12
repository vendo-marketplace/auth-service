package com.vendo.auth_service.port.auth.usecase;

public interface EmailVerificationUseCase {

    void send(String email);

    void resend(String email);

    void validate(String code);

}
