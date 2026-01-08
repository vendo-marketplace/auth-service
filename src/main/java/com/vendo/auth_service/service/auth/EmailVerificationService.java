package com.vendo.auth_service.service.auth;

import com.vendo.auth_service.http.user.dto.UserInfo;
import com.vendo.auth_service.service.otp.EmailOtpService;
import com.vendo.auth_service.system.redis.common.dto.ValidateRequest;
import com.vendo.auth_service.system.redis.common.namespace.otp.EmailVerificationOtpNamespace;
import com.vendo.integration.kafka.event.EmailOtpEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.vendo.integration.kafka.event.EmailOtpEvent.OtpEventType.EMAIL_VERIFICATION;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailOtpService emailOtpService;

    private final EmailVerificationOtpNamespace emailVerificationOtpNamespace;

    private final UserInfoProvider userInfoProvider;

    public void sendOtp(String email) {
        userInfoProvider.findByEmail(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(EMAIL_VERIFICATION)
                .build();
        emailOtpService.sendOtp(event, emailVerificationOtpNamespace);
    }

    public void resendOtp(String email) {
        userInfoProvider.ensureExists(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(EMAIL_VERIFICATION)
                .build();
        emailOtpService.resendOtp(event, emailVerificationOtpNamespace);
    }

    public void validate(String otp, ValidateRequest validateRequest) {
        UserInfo userInfo = userInfoProvider.findByEmail(validateRequest.email());

        emailOtpService.verifyOtpAndConsume(otp, validateRequest.email(), emailVerificationOtpNamespace);


        userInfoProvider.
        userCommandService.update(user.getId(), UserUpdateRequest.builder()
                .emailVerified(true)
                .build());
    }
}
