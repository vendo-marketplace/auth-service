package com.vendo.auth_service.adapter.out.otp;

import com.vendo.auth_service.adapter.otp.out.OtpSixDigitGenerator;
import com.vendo.auth_service.port.otp.OtpGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class OtpSixDigitGeneratorTest {

    @Test
    void generate_shouldAlwaysGenerateSixDigitNumber() {
        OtpGenerator otpGenerator = new OtpSixDigitGenerator();

        for (int i = 0; i < 100; i++) {
            String otp = otpGenerator.generate();
            assertThat(otp).hasSize(6).matches("[1-9]\\d{5}");
        }
    }
}
