package com.vendo.auth_service.application.otp;

import com.vendo.auth_service.adapter.otp.out.props.OtpNamespace;
import com.vendo.auth_service.application.otp.common.exception.InvalidOtpException;
import com.vendo.auth_service.port.otp.OtpStorage;
import com.vendo.redis_lib.config.PrefixProperties;
import com.vendo.redis_lib.exception.OtpExpiredException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
public class EmailOtpVerifierTest {

    @InjectMocks
    private EmailOtpVerifier emailOtpVerifier;
    @Mock
    private OtpStorage otpStorage;
    @Mock
    private OtpNamespace otpNamespace;

    @Mock
    private PrefixProperties emailPrefix;
    @Mock
    private PrefixProperties otpPrefix;
    @Mock
    private PrefixProperties attemptsPrefix;

    private static final String TEST_EMAIL = "email@gmail.com";
    private static final String TEST_OTP = "otp";

    @Test
    void verify_shouldReturnEmail_whenOtpValid() {
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);

        when(otpStorage.getValue("otp:" + TEST_OTP)).thenReturn(Optional.of(TEST_EMAIL));

        emailOtpVerifier.verify(TEST_OTP, otpNamespace);

        verify(otpStorage).getValue("otp:" + TEST_OTP);
        verify(otpStorage).deleteValues("otp:" + TEST_OTP);
    }

    @Test
    void verify_shouldThrowOtpExpiredException_whenOtpExpired() {
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);

        when(otpStorage.getValue("otp:" + TEST_OTP)).thenReturn(Optional.empty()).thenThrow(new OtpExpiredException("Otp session expired."));

        assertThatThrownBy(() -> emailOtpVerifier.verify(TEST_OTP, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        verify(otpStorage).getValue("otp:" + TEST_OTP);
    }

    @Test
    void verifyOtpEmail_shouldCleanUpOtpNamespaces_whenEmailsMatch() {
        String actualEmail = TEST_EMAIL;

        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpNamespace.getEmail()).thenReturn(emailPrefix);
        when(otpNamespace.getAttempts()).thenReturn(attemptsPrefix);

        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);
        when(emailPrefix.buildPrefix(TEST_EMAIL)).thenReturn("email:" + TEST_EMAIL);
        when(attemptsPrefix.buildPrefix(TEST_EMAIL)).thenReturn("attempts:" + TEST_EMAIL);

        when(otpStorage.getValue("otp:" + TEST_OTP)).thenReturn(Optional.of(actualEmail));

        emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace);

        verify(otpStorage).getValue(otpNamespace.getOtp().buildPrefix(TEST_OTP));
        verify(otpStorage).deleteValues(
                "otp:" + TEST_OTP,
                "email:" + TEST_EMAIL,
                "attempts:" + TEST_EMAIL
        );
    }

    @Test
    void verifyOtpEmail_shouldThrowOtpExpiredException_whenOtpExpired() {
        when(otpNamespace.getOtp()).thenReturn(otpPrefix);
        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);

        when(otpStorage.getValue("otp:" + TEST_OTP)).thenReturn(Optional.empty()).thenThrow(new OtpExpiredException("Otp session expired."));

        assertThatThrownBy(() -> emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace)).isInstanceOf(OtpExpiredException.class).hasMessage("Otp session expired.");

        verify(otpStorage).getValue("otp:" + TEST_OTP);
    }

    @Test
    void verifyOtpEmail_shouldThrowInvalidOtpException_whenEmailsNotMatch() {
        String actualEmail = "actual@gmail.com";

        when(otpNamespace.getOtp()).thenReturn(otpPrefix);

        when(otpPrefix.buildPrefix(TEST_OTP)).thenReturn("otp:" + TEST_OTP);

        when(otpStorage.getValue("otp:" + TEST_OTP)).thenReturn(Optional.of(actualEmail));

        assertThatThrownBy(() -> emailOtpVerifier.verifyOtpEmail(TEST_OTP, TEST_EMAIL, otpNamespace)).isInstanceOf(InvalidOtpException.class).hasMessage("Invalid otp.");

        assertThat(!TEST_EMAIL.equals(actualEmail));

        verify(otpStorage).getValue("otp:" + TEST_OTP);
        verify(otpStorage, never()).deleteValues(
                "otp:" + TEST_OTP,
                "email:" + actualEmail,
                "attempts:" + actualEmail
        );
    }
}
