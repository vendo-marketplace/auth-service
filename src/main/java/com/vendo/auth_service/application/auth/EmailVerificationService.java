package com.vendo.auth_service.application.auth;

import com.vendo.auth_service.adapter.otp.out.props.EmailVerificationOtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.auth.dto.UpdateUserRequest;
import com.vendo.auth_service.application.otp.OtpService;
import com.vendo.auth_service.application.otp.OtpSender;
import com.vendo.auth_service.domain.user.model.User;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.event_lib.otp.OtpEventType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final UserQueryPort userQueryPort;
    private final UserCommandPort userCommandPort;

    private final OtpService otpService;
    private final OtpSender otpSender;
    private final EmailVerificationOtpNamespace emailVerificationOtpNamespace;

    public void sendOtp(String email) {
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        otpSender.sendOtp(new OtpCommand(email, OtpEventType.EMAIL_VERIFICATION), emailVerificationOtpNamespace);
    }

    public void resendOtp(String email) {
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        otpSender.resendOtp(new OtpCommand(email, OtpEventType.EMAIL_VERIFICATION), emailVerificationOtpNamespace);
    }

    public void validate(String otp) {
        String email = otpService.consume(otp, emailVerificationOtpNamespace);
        User user = userQueryPort.getByEmail(email);
        user.throwIfVerified();
        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .emailVerified(true)
                .build());
    }

}
