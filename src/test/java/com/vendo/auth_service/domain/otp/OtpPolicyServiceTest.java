package com.vendo.auth_service.domain.otp;

import com.vendo.auth_service.application.otp.common.exception.TooManyOtpRequestsException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class OtpPolicyServiceTest {

    private final OtpPolicyService otpPolicyService = new OtpPolicyService();

    @Test
    void throwOrIncreaseAttempts_shouldIncreaseAttempts_whenBelowLimit() {
        int result = otpPolicyService.throwOrIncreaseAttempts(0);

        assertThat(result).isEqualTo(1);
    }

    @Test
    void throwOrIncreaseAttempts_shouldIncreaseAttempts_whenOneAttempt() {
        int result = otpPolicyService.throwOrIncreaseAttempts(1);

        assertThat(result).isEqualTo(2);
    }

    @Test
    void throwOrIncreaseAttempts_shouldIncreaseAttempts_whenTwoAttempts() {
        int result = otpPolicyService.throwOrIncreaseAttempts(2);

        assertThat(result).isEqualTo(3);
    }

    @Test
    void throwOrIncreaseAttempts_shouldThrowException_whenAttemptsReachedLimit() {
        assertThatThrownBy(() ->
                otpPolicyService.throwOrIncreaseAttempts(3)
        )
                .isInstanceOf(TooManyOtpRequestsException.class)
                .hasMessage("Reached maximum attempts.");
    }

    @Test
    void throwOrIncreaseAttempts_shouldThrowException_whenAttemptsAboveLimit() {
        assertThatThrownBy(() ->
                otpPolicyService.throwOrIncreaseAttempts(5)
        )
                .isInstanceOf(TooManyOtpRequestsException.class);
    }

}
