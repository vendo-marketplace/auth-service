package com.vendo.auth_service.domain.otp;

import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.application.otp.common.exception.OtpAlreadySentException;
import com.vendo.auth_service.application.otp.common.exception.TooManyOtpRequestsException;
import org.springframework.stereotype.Service;

@Service
public class OtpPolicyService {
    public void checkIfInactive(boolean hasActive){
        if(!hasActive){
            throw new OtpAlreadySentException("Otp has already sent.");
        }
    }
    public void checkIfEmailMatches(String email1, String email2){
        if(!email2.equals(email1)){
            throw new InvalidOtpException("Invalid otp.");
        }
    }
    public int checkAndIncreaseAttempts(int attempt){
        if (attempt >= 3) {
            throw new TooManyOtpRequestsException("Reached maximum attempts.");
        }
        return attempt + 1;
    }
}