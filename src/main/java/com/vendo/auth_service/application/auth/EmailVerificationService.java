package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.otp.out.props.EmailVerificationOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpVerifier;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.OtpEventType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;

    private final OtpVerifier otpVerifier;
    private final OtpService otpService;
    private final EmailVerificationOtpNamespace emailVerificationOtpNamespace;

    public void sendOtp(String email) {
        userQueryPort.getByEmail(email);
        otpService.sendOtp(new OtpCommand(email, OtpEventType.EMAIL_VERIFICATION), emailVerificationOtpNamespace);
    }

    public void resendOtp(String email) {
        userQueryPort.getByEmail(email);
        otpService.resendOtp(new OtpCommand(email, OtpEventType.EMAIL_VERIFICATION), emailVerificationOtpNamespace);
    }

    @Transactional
    public void validate(String otp) {
        String email = otpVerifier.verify(otp, emailVerificationOtpNamespace);
        User user = userQueryPort.getByEmail(email);
        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .emailVerified(true)
                .build());
    }

}
