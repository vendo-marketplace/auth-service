package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.application.auth.command.ValidateCommand;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.otp.service.EmailOtpService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.adapter.otp.out.props.EmailVerificationOtpNamespace;
import com.vendo.integration.kafka.event.EmailOtpEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.vendo.integration.kafka.event.EmailOtpEvent.OtpEventType.EMAIL_VERIFICATION;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailOtpService emailOtpService;

    private final EmailVerificationOtpNamespace emailVerificationOtpNamespace;

    private final UserQueryPort userQueryPort;

    private final UserCommandPort userCommandPort;

    public void sendOtp(String email) {
        emailOtpService.sendOtp(createVerificationEvent(email), emailVerificationOtpNamespace);
    }

    public void resendOtp(String email) {
        emailOtpService.resendOtp(createVerificationEvent(email), emailVerificationOtpNamespace);
    }

    private EmailOtpEvent createVerificationEvent(String email){
        userQueryPort.getByEmail(email);

        return EmailOtpEvent.builder()
                .email(email)
                .otpEventType(EMAIL_VERIFICATION)
                .build();
    }

    public void validate(String otp, ValidateCommand command) {
        User user = userQueryPort.getByEmail(command.email());

        emailOtpService.verifyOtpAndConsume(otp, command.email(), emailVerificationOtpNamespace);

        userCommandPort.update(user.id(), User.builder()
                .emailVerified(true)
                .build());
    }
}
