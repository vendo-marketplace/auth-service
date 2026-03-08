package com.vendo.auth_service.adapter.otp.out;

import com.vendo.auth_service.port.otp.OtpGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class OtpSixDigitGenerator implements OtpGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String generate() {
        int otp = 100000 + RANDOM.nextInt(900000);
        return String.valueOf(otp);
    }
}
