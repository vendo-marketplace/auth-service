package com.vendo.auth_service.application;

import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.application.otp.EmailOtpService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.system.redis.common.dto.ResetPasswordRequest;
import com.vendo.auth_service.system.redis.common.namespace.otp.PasswordRecoveryOtpNamespace;
import com.vendo.integration.kafka.event.EmailOtpEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.vendo.integration.kafka.event.EmailOtpEvent.OtpEventType.PASSWORD_RECOVERY;

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

    public void resetPassword(String otp, ResetPasswordRequest resetPasswordRequest) {
        String email = emailOtpService.verifyOtpAndConsume(otp, null, passwordRecoveryOtpNamespace);

        User user = userQueryPort.getByEmail(email);

        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .password(passwordEncoder.encode(resetPasswordRequest.password()))
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
