package com.vendo.auth_service.application.email;

import com.vendo.auth_service.domain.user.common.dto.UpdateUserRequest;
import com.vendo.auth_service.domain.user.common.dto.User;
import com.vendo.auth_service.application.otp.service.EmailOtpService;
import com.vendo.auth_service.port.user.UserCommandPort;
import com.vendo.auth_service.port.user.UserQueryPort;
import com.vendo.auth_service.adapter.out.db.redis.common.dto.ValidateRequest;
import com.vendo.auth_service.adapter.out.db.redis.common.namespace.otp.EmailVerificationOtpNamespace;
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

    public void validate(String otp, ValidateRequest validateRequest) {
        User user = userQueryPort.getByEmail(validateRequest.email());

        emailOtpService.verifyOtpAndConsume(otp, validateRequest.email(), emailVerificationOtpNamespace);

        userCommandPort.update(user.id(), UpdateUserRequest.builder()
                .emailVerified(true)
                .build());
    }
}
