package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.auth.command.OtpCommand;
import com.vendo.auth_service.domain.otp.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.otp.OtpPolicyService;
import com.vendo.auth_service.port.otp.OtpEmailNotificationPort;
import com.vendo.auth_service.port.otp.OtpGenerator;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.auth_service.port.otp.StorageValue;
import com.vendo.event_lib.otp.EmailOtpEvent;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EmailOtpSender implements OtpSender {

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
        int attempts = getAttemptsOrThrow(command.email(), otpNamespace);
        otpEmailNotificationPort.sendOtpEmailNotification(new EmailOtpEvent(otp, command.email(), command.type()));
        increaseAttempts(attempts, command.email(), otpNamespace);
    }

    private void throwIfOtpAlreadySent(String email, OtpNamespace namespace) {
        boolean activeKey = otpStorage.hasActiveKey(namespace.getEmail().buildPrefix(email));
        if (activeKey) {
            throw new OtpAlreadySentException("Otp already sent.");
        }
    }

    private void saveOtpNamespaces(String otp, String email, OtpNamespace namespace) {
        Map<String, StorageValue> values = Map.of(
                namespace.getOtp().buildPrefix(otp), new StorageValue(email, namespace.getOtp().ttl()),
                namespace.getEmail().buildPrefix(email), new StorageValue(otp, namespace.getEmail().ttl())
        );
        otpStorage.saveValues(values);
    }

    private String getOtpOrThrow(String email, OtpNamespace otpNamespace) {
        return otpStorage.getValue(otpNamespace.getEmail().buildPrefix(email))
                .orElseThrow(() -> new OtpExpiredException("No active OTP session found."));
    }

    private int getAttemptsOrThrow(String email, OtpNamespace otpNamespace) {
        Optional<String> otpStorageValue = otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(email));
        int attempts = otpStorageValue.map(Integer::parseInt).orElse(0);
        OtpPolicyService.throwIfTooManyAttempts(attempts);
        return attempts;
    }

    private void increaseAttempts(int attempts, String email, OtpNamespace otpNamespace) {
        otpStorage.saveValue(
                otpNamespace.getAttempts().buildPrefix(email),
                String.valueOf(++attempts),
                otpNamespace.getAttempts().ttl());
    }

}
