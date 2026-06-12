package com.vendo.auth_service.domain.otp;

import com.vendo.auth_service.application.otp.common.exception.TooManyOtpRequestsException;

public class OtpPolicyService {

    public static int throwOrIncreaseAttempts(int attempt) {
        if (attempt >= 3) {
            throw new TooManyOtpRequestsException("Reached maximum attempts.");
        }
        return attempt + 1;
    }

}