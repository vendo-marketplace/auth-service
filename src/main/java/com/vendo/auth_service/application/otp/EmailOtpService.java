package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.otp.OtpPolicyService;
import com.vendo.auth_service.port.otp.OtpEmailNotificationPort;
import com.vendo.auth_service.port.otp.OtpGenerator;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.event_lib.otp.EmailOtpEvent;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EmailOtpService implements OtpService {

    private final OtpStorage otpStorage;
    private final OtpGenerator otpGenerator;
    private final OtpEmailNotificationPort otpEmailNotificationPort;

    @Override
    public void sendOtp(OtpCommand command, OtpNamespace namespace) {
        throwIfOtpAlreadySent(command.email(), namespace);
        String otp = otpGenerator.generate();
        saveOtpNamespaces(otp, command.email(), namespace);
        otpEmailNotificationPort.sendOtpEmailNotification(new EmailOtpEvent(otp, command.email(), command.type()));
    }

    @Override
    public void resendOtp(OtpCommand command, OtpNamespace otpNamespace) {
        String otp = getOtpOrThrow(command.email(), otpNamespace);
        increaseResendAttemptsOrThrow(command.email(), otpNamespace);
        otpEmailNotificationPort.sendOtpEmailNotification(new EmailOtpEvent(otp, command.email(), command.type()));
    }

    private void throwIfOtpAlreadySent(String email, OtpNamespace namespace) {
        boolean activeKey = otpStorage.hasActiveKey(namespace.getEmail().buildPrefix(email));
        if (activeKey) {
            throw new OtpAlreadySentException("Otp already sent.");
        }
    }

    private void saveOtpNamespaces(String otp, String email, OtpNamespace namespace) {
        otpStorage.saveValue(namespace.getOtp().buildPrefix(otp), email, namespace.getOtp().ttl());
        otpStorage.saveValue(namespace.getEmail().buildPrefix(email), otp, namespace.getEmail().ttl());
    }

    private String getOtpOrThrow(String email, OtpNamespace otpNamespace) {
        return otpStorage.getValue(otpNamespace.getEmail().buildPrefix(email))
                .orElseThrow(() -> new OtpExpiredException("No active OTP session found."));
    }

    private void increaseResendAttemptsOrThrow(String email, OtpNamespace otpNamespace) {
        Optional<String> attempts = otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(email));
        int attempt = OtpPolicyService.throwOrIncreaseAttempts(attempts.map(Integer::parseInt).orElse(0));

        otpStorage.saveValue(
                otpNamespace.getAttempts().buildPrefix(email),
                String.valueOf(attempt),
                otpNamespace.getAttempts().ttl());
    }

}
