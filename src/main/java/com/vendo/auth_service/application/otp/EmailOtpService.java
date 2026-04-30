package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.otp.OtpPolicyService;
import com.vendo.auth_service.port.otp.OtpEmailNotificationPort;
import com.vendo.auth_service.port.otp.OtpGenerator;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.event_lib.otp.EmailOtpEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EmailOtpService implements OtpService {

    private final OtpStorage otpStorage;
    private final OtpGenerator otpGenerator;
    private final OtpEmailNotificationPort otpEmailNotificationPort;
    private final OtpPolicyService otpPolicyService;

    @Override
    public void sendOtp(OtpCommand command, OtpNamespace namespace) {
        throwIfOtpAlreadySent(command.email(), namespace);
        String otp = otpGenerator.generate();
        saveOtpNamespaces(otp, command.email(), namespace);
        otpEmailNotificationPort.sendOtpEmailNotification(new EmailOtpEvent(otp, command.email(), command.type()));
    }

    @Override
    public void resendOtp(OtpCommand command, OtpNamespace otpNamespace) {
        String otp = getOtpOrGenerate(command.email(), otpNamespace);
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

    private String getOtpOrGenerate(String email, OtpNamespace otpNamespace) {
        Optional<String> otp = otpStorage.getValue(otpNamespace.getEmail().buildPrefix(email));

        if (otp.isEmpty()) {
            String newOtp = otpGenerator.generate();
            otpStorage.saveValue(otpNamespace.getEmail().buildPrefix(email), newOtp, otpNamespace.getOtp().ttl());
            return newOtp;
        }

        return otp.get();
    }

    private void increaseResendAttemptsOrThrow(String email, OtpNamespace otpNamespace) {
        Optional<String> attempts = otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(email));
        int attempt = otpPolicyService.throwOrIncreaseAttempts(attempts.map(Integer::parseInt).orElse(0));

        otpStorage.saveValue(
                otpNamespace.getAttempts().buildPrefix(email),
                String.valueOf(attempt),
                otpNamespace.getAttempts().ttl());
    }

}
