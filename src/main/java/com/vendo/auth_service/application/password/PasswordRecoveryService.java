package com.vendo.auth_service.application.password;

import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.OtpVerifier;
import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.OtpEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordRecoveryService {

    private final PasswordEncoder passwordEncoder;
    private final PasswordRecoveryOtpNamespace passwordRecoveryOtpNamespace;

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;

    private final OtpService otpService;
    private final OtpVerifier otpVerifier;

    public void forgotPassword(String email) {
        userQueryPort.getByEmail(email);
        otpService.sendOtp(new OtpCommand(email, OtpEventType.PASSWORD_RECOVERY), passwordRecoveryOtpNamespace);
    }

    public void resetPassword(String otp, ResetPasswordCommand command) {
        String email = otpVerifier.verify(otp, passwordRecoveryOtpNamespace);
        User user = userQueryPort.getByEmail(email);
        userCommandPort.update(user.id(), User.builder()
                .password(passwordEncoder.encode(command.password()))
                .build());
    }

    public void resendOtp(String email) {
        userQueryPort.getByEmail(email);
        otpService.resendOtp(new OtpCommand(email, OtpEventType.PASSWORD_RECOVERY), passwordRecoveryOtpNamespace);
    }
}
