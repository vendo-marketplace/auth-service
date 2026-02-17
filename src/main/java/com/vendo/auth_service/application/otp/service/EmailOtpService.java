package com.vendo.auth_service.application.otp.service;

import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.domain.otp.OtpPolicyService;
import com.vendo.auth_service.port.otp.OtpEmailNotificationPort;
import com.vendo.auth_service.port.otp.OtpGenerator;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.event_lib.EmailOtpEvent;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private final OtpStorage otpStorage;

    private final OtpGenerator otpGenerator;

    private final OtpPolicyService otpPolicyService;

    private final OtpEmailNotificationPort otpEmailNotificationPort;

    public void sendOtp(EmailOtpEvent event, OtpNamespace otpNamespace) {
        boolean activeKey = otpStorage.hasActiveKey(otpNamespace.getEmail().buildPrefix(event.getEmail()));
        if (activeKey) {
            throw new OtpAlreadySentException("Otp has already sent.");
        }

        String otp = otpGenerator.generate();

        otpStorage.saveValue(otpNamespace.getOtp().buildPrefix(otp), event.getEmail(), otpNamespace.getOtp().getTtl());
        otpStorage.saveValue(otpNamespace.getEmail().buildPrefix(event.getEmail()), otp, otpNamespace.getEmail().getTtl());

        event.setOtp(otp);
        otpEmailNotificationPort.sendOtpEmailNotification(event);
    }

    public void resendOtp(EmailOtpEvent event, OtpNamespace otpNamespace) {
        otpStorage.getValue(otpNamespace.getEmail().buildPrefix(event.getEmail()))
                .orElseThrow(() -> new OtpExpiredException("Otp session expired."));

        increaseResendAttemptsOrThrow(event.getEmail(), otpNamespace);

        String otp = getOtpOrGenerate(event.getEmail(), otpNamespace);
        event.setOtp(otp);

        otpEmailNotificationPort.sendOtpEmailNotification(event);
    }

    public void verifyEmailByOtp(String otp, String expectedEmail, OtpNamespace namespace) {
        String actualEmail = otpStorage.getValue(namespace.getOtp().buildPrefix(otp))
                .orElseThrow(() -> new OtpExpiredException("Otp session expired."));

        if (expectedEmail != null && !expectedEmail.equals(actualEmail)) {
            throw new InvalidOtpException("Invalid otp.");
        }

        otpStorage.deleteValues(
                namespace.getOtp().buildPrefix(otp),
                namespace.getEmail().buildPrefix(actualEmail),
                namespace.getAttempts().buildPrefix(actualEmail)
        );
    }

    public String verifyByOtp(String otp, OtpNamespace namespace) {
        String email = otpStorage.getValue(namespace.getOtp().buildPrefix(otp))
                .orElseThrow(() -> new OtpExpiredException("Otp session expired."));

        otpStorage.deleteValues(namespace.getOtp().buildPrefix(otp));

        return email;
    }

    private void increaseResendAttemptsOrThrow(String email, OtpNamespace otpNamespace) {
        Optional<String> attempts = otpStorage.getValue(otpNamespace.getAttempts().buildPrefix(email));
        int attempt = otpPolicyService.throwOrIncreaseAttempts(attempts.map(Integer::parseInt).orElse(0));

        otpStorage.saveValue(
                otpNamespace.getAttempts().buildPrefix(email),
                String.valueOf(attempt),
                otpNamespace.getAttempts().getTtl());
    }

    private String getOtpOrGenerate(String email, OtpNamespace otpNamespace) {
        Optional<String> otp = otpStorage.getValue(otpNamespace.getEmail().buildPrefix(email));

        if (otp.isEmpty()) {
            String newOtp = otpGenerator.generate();
            otpStorage.saveValue(otpNamespace.getEmail().buildPrefix(email), newOtp, otpNamespace.getOtp().getTtl());
            return newOtp;
        }

        return otp.get();
    }
}
