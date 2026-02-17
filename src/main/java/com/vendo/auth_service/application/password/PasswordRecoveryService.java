package com.vendo.auth_service.application.password;

import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.application.otp.service.EmailOtpService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.event_lib.EmailOtpEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.vendo.event_lib.EmailOtpEvent.OtpEventType.PASSWORD_RECOVERY;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordRecoveryService {

    private final PasswordEncoder passwordEncoder;

    private final PasswordRecoveryOtpNamespace passwordRecoveryOtpNamespace;

    private final UserQueryPort userQueryPort;

    private final UserCommandPort userCommandPort;

    private final EmailOtpService emailOtpService;

    public void forgotPassword(String email) {
        userQueryPort.getByEmail(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(PASSWORD_RECOVERY)
                .build();
        emailOtpService.sendOtp(event, passwordRecoveryOtpNamespace);
    }

    public void resetPassword(String otp, ResetPasswordCommand command) {
        String email = emailOtpService.verifyByOtp(otp, passwordRecoveryOtpNamespace);

        User user = userQueryPort.getByEmail(email);

        userCommandPort.update(user.id(), User.builder()
                .password(passwordEncoder.encode(command.password()))
                .build());
    }

    public void resendOtp(String email) {
        userQueryPort.getByEmail(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(PASSWORD_RECOVERY)
                .build();
        emailOtpService.resendOtp(event, passwordRecoveryOtpNamespace);
    }
}
