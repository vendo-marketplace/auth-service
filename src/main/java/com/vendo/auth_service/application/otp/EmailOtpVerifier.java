package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpVerifier implements OtpVerifier {

    private final OtpStorage otpStorage;

    @Override
    public String verify(String otp, OtpNamespace namespace) {
        String email = getEmailByOtpOrThrow(otp, namespace);
        otpStorage.deleteValues(namespace.getOtp().buildPrefix(otp));
        return email;
    }

    @Override
    public void verifyOtpEmail(String otp, String expectedEmail, OtpNamespace namespace) {
        String actualEmail = getEmailByOtpOrThrow(otp, namespace);

        if (!expectedEmail.equals(actualEmail)) {
            throw new InvalidOtpException("Invalid otp.");
        }

        cleanUpOtpNamespaces(otp, actualEmail, namespace);
    }

    private void cleanUpOtpNamespaces(String otp, String email, OtpNamespace namespace) {
        otpStorage.deleteValues(
                namespace.getOtp().buildPrefix(otp),
                namespace.getEmail().buildPrefix(email),
                namespace.getAttempts().buildPrefix(email)
        );
    }

    private String getEmailByOtpOrThrow(String otp, OtpNamespace namespace) {
        return otpStorage.getValue(namespace.getOtp().buildPrefix(otp))
                .orElseThrow(() -> new OtpExpiredException("Otp session expired."));
    }
}
