package com.vendo.auth_service.domain.otp;

import com.vendo.auth_service.domain.otp.exception.TooManyOtpRequestsException;

public class OtpPolicyService {

    public static void throwIfTooManyAttempts(int attempt) {
        if (attempt >= 3) {
            throw new TooManyOtpRequestsException("Reached maximum attempts.");
        }
    }

}