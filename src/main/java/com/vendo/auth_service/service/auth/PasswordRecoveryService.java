package com.vendo.auth_service.service.auth;

import com.vendo.auth_service.db.command.UserCommandService;
import com.vendo.auth_service.db.model.User;
import com.vendo.auth_service.db.query.UserQueryService;
import com.vendo.auth_service.service.otp.EmailOtpService;
import com.vendo.auth_service.system.redis.common.dto.ResetPasswordRequest;
import com.vendo.auth_service.system.redis.common.namespace.otp.PasswordRecoveryOtpNamespace;
import com.vendo.auth_service.web.dto.UserUpdateRequest;
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

    private final UserInfoProvider userInfoProvider;

    private final EmailOtpService emailOtpService;

    public void forgotPassword(String email) {
        userInfoProvider.findByEmail(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(PASSWORD_RECOVERY)
                .build();
        emailOtpService.sendOtp(event, passwordRecoveryOtpNamespace);
    }

    public void resetPassword(String otp, ResetPasswordRequest resetPasswordRequest) {
        String email = emailOtpService.verifyOtpAndConsume(otp, null, passwordRecoveryOtpNamespace);

        User user = userQueryService.loadUserByUsername(email);
        userCommandService.update(user.getId(), UserUpdateRequest.builder()
                .password(passwordEncoder.encode(resetPasswordRequest.password()))
                .build());
    }

    public void resendOtp(String email) {
        userQueryService.loadUserByUsername(email);

        EmailOtpEvent event = EmailOtpEvent.builder()
                .email(email)
                .otpEventType(PASSWORD_RECOVERY)
                .build();
        emailOtpService.resendOtp(event, passwordRecoveryOtpNamespace);
    }
}
