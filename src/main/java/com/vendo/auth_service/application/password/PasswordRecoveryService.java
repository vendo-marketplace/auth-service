package com.vendo.auth_service.application.password;

import com.vendo.auth_service.adapter.otp.out.props.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.OtpVerifier;
import com.vendo.auth_service.application.password.command.ResetPasswordCommand;
import com.vendo.auth_service.domain.user.exception.SamePasswordException;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.security.PasswordHashingPort;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserLookupPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.otp.OtpEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordRecoveryService {

    private final PasswordRecoveryOtpNamespace passwordRecoveryOtpNamespace;

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;
    private final UserLookupPort userLookupPort;
    private final PasswordHashingPort passwordHashingPort;

    private final OtpService otpService;
    private final OtpVerifier otpVerifier;

    public void forgotPassword(String email) {
        userLookupPort.requireExistence(email);
        otpService.sendOtp(new OtpCommand(email, OtpEventType.PASSWORD_RECOVERY), passwordRecoveryOtpNamespace);
    }

    public void resetPassword(String otp, ResetPasswordCommand command) {
        String email = otpVerifier.verify(otp, passwordRecoveryOtpNamespace);
        User user = userQueryPort.getByEmail(email);

        validateNotSamePassword(command.password(), user.password());

        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .password(passwordHashingPort.hash(command.password()))
                .build());
    }

    private void validateNotSamePassword(String newPassword, String oldHashedPassword) {
        if (passwordHashingPort.matches(newPassword, oldHashedPassword)) {
            throw new SamePasswordException("The new password cannot be the same as the current password.");
        }
    }

    public void resendOtp(String email) {
        userLookupPort.requireExistence(email);
        otpService.resendOtp(new OtpCommand(email, OtpEventType.PASSWORD_RECOVERY), passwordRecoveryOtpNamespace);
    }

}
